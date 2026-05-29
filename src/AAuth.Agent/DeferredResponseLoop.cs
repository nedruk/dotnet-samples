using System.Net;
using System.Text.Json;
using AAuth.Core.Headers;

namespace AAuth.Agent;

/// <summary>
/// Error information from a deferred response.
/// </summary>
public sealed record AAuthError(string ErrorCode, string? ErrorDescription = null);

/// <summary>
/// Result of a deferred response polling loop.
/// </summary>
public sealed record DeferredResult(HttpResponseMessage Response, AAuthError? Error = null);

/// <summary>
/// Options for the deferred response polling loop.
/// </summary>
public sealed class DeferredOptions
{
    public string? InteractionUrl { get; init; }
    public string? InteractionCode { get; init; }
    public Func<string, string, Task>? OnInteraction { get; init; }
    public Func<string, Task<string>>? OnClarification { get; init; }
    public int MaxPollDurationSeconds { get; init; } = 300;
    public int PreferWaitSeconds { get; init; } = 45;

    /// <summary>
    /// The origin URL of the server that issued the deferred response.
    /// Used to verify same-origin Location URLs per spec.
    /// </summary>
    public string? OriginalRequestOrigin { get; init; }
}

/// <summary>
/// Implements the AAuth deferred response polling state machine.
/// </summary>
public static class DeferredResponseLoop
{
    /// <summary>
    /// Poll a 202 Location URL until a terminal response is received.
    /// Implements the full state machine from the AAuth spec.
    /// </summary>
    public static async Task<DeferredResult> PollAsync(
        HttpClient httpClient,
        string locationUrl,
        DeferredOptions options,
        CancellationToken cancellationToken = default)
    {
        // Verify same-origin: Location URL MUST be on the same origin as the responding server
        var locationUri = new Uri(locationUrl);
        if (options.OriginalRequestOrigin is not null)
        {
            var originalOrigin = new Uri(options.OriginalRequestOrigin);
            if (!string.Equals(locationUri.GetLeftPart(UriPartial.Authority),
                originalOrigin.GetLeftPart(UriPartial.Authority), StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"Location URL origin '{locationUri.GetLeftPart(UriPartial.Authority)}' does not match " +
                    $"server origin '{originalOrigin.GetLeftPart(UriPartial.Authority)}'");
            }
        }

        var deadline = DateTimeOffset.UtcNow.AddSeconds(options.MaxPollDurationSeconds);
        var backoffMs = 1000;

        // Notify about initial interaction
        if (options.InteractionUrl is not null && options.InteractionCode is not null &&
            options.OnInteraction is not null)
        {
            await options.OnInteraction(options.InteractionUrl, options.InteractionCode);
        }

        while (DateTimeOffset.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var request = new HttpRequestMessage(HttpMethod.Get, locationUrl);
            request.Headers.TryAddWithoutValidation("Prefer", $"wait={options.PreferWaitSeconds}");

            var response = await httpClient.SendAsync(request, cancellationToken);
            var status = response.StatusCode;

            // Terminal responses
            if (status is HttpStatusCode.OK or HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized
                or HttpStatusCode.Forbidden or HttpStatusCode.RequestTimeout or HttpStatusCode.Gone
                or (HttpStatusCode)500)
            {
                return new DeferredResult(response, await ParseErrorBodyAsync(response));
            }

            if (status == HttpStatusCode.Accepted) // 202
            {
                // Check for clarification
                if (response.Content.Headers.ContentType?.MediaType == "application/json" &&
                    options.OnClarification is not null)
                {
                    try
                    {
                        var body = await response.Content.ReadAsStringAsync(cancellationToken);
                        var json = JsonSerializer.Deserialize<JsonElement>(body);

                        if (json.TryGetProperty("clarification", out var clarificationProp))
                        {
                            var question = clarificationProp.GetString()!;
                            var answer = await options.OnClarification(question);

                            // POST clarification response back
                            var postContent = new StringContent(
                                JsonSerializer.Serialize(new { clarification_response = answer }),
                                System.Text.Encoding.UTF8,
                                "application/json");
                            await httpClient.PostAsync(locationUrl, postContent, cancellationToken);
                        }
                    }
                    catch
                    {
                        // Malformed JSON — skip clarification, continue polling
                    }
                }

                // Check for interaction in AAuth-Requirement header
                if (response.Headers.TryGetValues("aauth-requirement", out var reqValues))
                {
                    try
                    {
                        var challenge = AAuthRequirement.Parse(reqValues.First());
                        if (challenge.Requirement == "interaction" && challenge.Url is not null &&
                            challenge.Code is not null && options.OnInteraction is not null)
                        {
                            await options.OnInteraction(challenge.Url, challenge.Code);
                        }
                    }
                    catch
                    {
                        // Invalid header — ignore
                    }
                }

                var waitMs = GetRetryDelay(response, backoffMs);
                await Task.Delay(waitMs, cancellationToken);
                backoffMs = Math.Min(backoffMs * 2, 5000);
                continue;
            }

            if (status == HttpStatusCode.ServiceUnavailable) // 503
            {
                var waitMs = GetRetryDelay(response, backoffMs);
                await Task.Delay(waitMs, cancellationToken);
                backoffMs = Math.Min(backoffMs * 2, 30000);
                continue;
            }

            if (status == (HttpStatusCode)429) // Too Many Requests
            {
                backoffMs += 5000;
                var waitMs = GetRetryDelay(response, backoffMs);
                await Task.Delay(waitMs, cancellationToken);
                continue;
            }

            if (status == HttpStatusCode.PaymentRequired) // 402
            {
                // Spec: 402 means payment required — settle payment and poll Location
                // The 402 response includes a Location header for polling after payment
                var paymentLocation = response.Headers.Location?.ToString();
                if (paymentLocation is not null)
                {
                    if (!Uri.IsWellFormedUriString(paymentLocation, UriKind.Absolute))
                        paymentLocation = new Uri(new Uri(locationUrl), paymentLocation).ToString();
                    locationUrl = paymentLocation;
                    var waitMs = GetRetryDelay(response, backoffMs);
                    await Task.Delay(waitMs, cancellationToken);
                    continue;
                }
                // No Location header — treat as terminal
                return new DeferredResult(response, await ParseErrorBodyAsync(response));
            }

            // Unexpected status — treat as terminal
            return new DeferredResult(response, await ParseErrorBodyAsync(response));
        }

        throw new TimeoutException($"Deferred response polling timed out after {options.MaxPollDurationSeconds}s");
    }

    private static int GetRetryDelay(HttpResponseMessage response, int fallbackMs)
    {
        if (response.Headers.RetryAfter?.Delta is { } delta)
            return (int)delta.TotalMilliseconds;

        if (response.Headers.RetryAfter?.Date is { } date)
        {
            var delay = date - DateTimeOffset.UtcNow;
            return delay > TimeSpan.Zero ? (int)delay.TotalMilliseconds : 0;
        }

        return fallbackMs;
    }

    private static async Task<AAuthError?> ParseErrorBodyAsync(HttpResponseMessage response)
    {
        if (response.IsSuccessStatusCode) return null;
        if (response.Content.Headers.ContentType?.MediaType != "application/json") return null;

        try
        {
            var body = await response.Content.ReadAsStringAsync();
            var json = JsonSerializer.Deserialize<JsonElement>(body);

            if (json.TryGetProperty("error", out var errorProp))
            {
                var errorCode = errorProp.GetString() ?? "unknown";
                string? description = null;
                if (json.TryGetProperty("error_description", out var descProp))
                    description = descProp.GetString();
                return new AAuthError(errorCode, description);
            }
        }
        catch
        {
            // Malformed JSON
        }

        return null;
    }
}
