using System.Net;
using System.Text;
using System.Text.Json;
using AAuth.Agent;
using AAuth.Core.Headers;
using Xunit;

namespace AAuth.Agent.Tests;

/// <summary>
/// Tests for <see cref="DeferredResponseLoop"/> covering the deferred/interaction grant flow.
/// Mirrors the TypeScript e2e "Deferred/interaction grant" suite.
/// </summary>
public class DeferredResponseLoopTests
{
    // ──────────────────────────────────────────────────────────────
    // Test: Token endpoint returns 202 → poll → 200 with auth_token
    // Mirrors TypeScript e2e "Deferred grant: 202 → interaction → poll → success"
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task DeferredGrant_202_Poll_Success_ReturnsAuthToken()
    {
        var callCount = 0;
        var mockHandler = new MockHttpHandler(_ =>
        {
            callCount++;
            if (callCount == 1)
            {
                // First poll: still pending
                return new HttpResponseMessage(HttpStatusCode.Accepted);
            }

            // Second poll: resolved
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    JsonSerializer.Serialize(new { auth_token = "eyJ.resolved.token", expires_in = 3600 }),
                    Encoding.UTF8, "application/json")
            };
        });

        var client = new HttpClient(mockHandler);

        var result = await DeferredResponseLoop.PollAsync(
            client,
            "https://ps.example.com/pending/abc123",
            new DeferredOptions
            {
                MaxPollDurationSeconds = 10,
                PreferWaitSeconds = 0
            });

        Assert.Equal(HttpStatusCode.OK, result.Response.StatusCode);
        var body = await result.Response.Content.ReadAsStringAsync();
        var json = JsonSerializer.Deserialize<JsonElement>(body);
        Assert.Equal("eyJ.resolved.token", json.GetProperty("auth_token").GetString());
        Assert.Equal(3600, json.GetProperty("expires_in").GetInt32());
    }

    // ──────────────────────────────────────────────────────────────
    // Test: 202 with interaction → onInteraction called → poll resolves
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task DeferredGrant_202_Interaction_Poll_Success()
    {
        string? receivedUrl = null;
        string? receivedCode = null;

        var callCount = 0;
        var mockHandler = new MockHttpHandler(_ =>
        {
            callCount++;
            if (callCount == 1)
            {
                // First poll: still pending, with interaction requirement header
                var resp = new HttpResponseMessage(HttpStatusCode.Accepted);
                resp.Headers.TryAddWithoutValidation("aauth-requirement",
                    AAuthRequirement.BuildInteraction(
                        "https://ps.example.com/interact/xyz",
                        "USERCODE42"));
                return resp;
            }

            // Second poll: resolved
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    JsonSerializer.Serialize(new { auth_token = "final_token", expires_in = 1800 }),
                    Encoding.UTF8, "application/json")
            };
        });

        var client = new HttpClient(mockHandler);

        var result = await DeferredResponseLoop.PollAsync(
            client,
            "https://ps.example.com/pending/def456",
            new DeferredOptions
            {
                MaxPollDurationSeconds = 10,
                PreferWaitSeconds = 0,
                OnInteraction = (url, code) =>
                {
                    receivedUrl = url;
                    receivedCode = code;
                    return Task.CompletedTask;
                }
            });

        Assert.Equal(HttpStatusCode.OK, result.Response.StatusCode);
        Assert.Equal("https://ps.example.com/interact/xyz", receivedUrl);
        Assert.Equal("USERCODE42", receivedCode);
    }

    // ──────────────────────────────────────────────────────────────
    // Test: Initial interaction callback fires before polling begins
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task DeferredGrant_InitialInteraction_CallsOnInteraction()
    {
        string? receivedUrl = null;
        string? receivedCode = null;

        var mockHandler = new MockHttpHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    JsonSerializer.Serialize(new { auth_token = "tok", expires_in = 600 }),
                    Encoding.UTF8, "application/json")
            });

        var client = new HttpClient(mockHandler);

        await DeferredResponseLoop.PollAsync(
            client,
            "https://ps.example.com/pending/ghi789",
            new DeferredOptions
            {
                InteractionUrl = "https://ps.example.com/interact/init",
                InteractionCode = "INITCODE",
                OnInteraction = (url, code) =>
                {
                    receivedUrl = url;
                    receivedCode = code;
                    return Task.CompletedTask;
                },
                MaxPollDurationSeconds = 10,
                PreferWaitSeconds = 0
            });

        Assert.Equal("https://ps.example.com/interact/init", receivedUrl);
        Assert.Equal("INITCODE", receivedCode);
    }

    // ──────────────────────────────────────────────────────────────
    // Test: Clarification flow — 202 with clarification → callback → POST → poll resolves
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task DeferredGrant_Clarification_CallsCallback_PostsResponse()
    {
        string? receivedQuestion = null;
        HttpRequestMessage? postRequest = null;
        var callCount = 0;

        var mockHandler = new MockHttpHandler(request =>
        {
            callCount++;

            if (callCount == 1)
            {
                // First GET poll: clarification needed
                return new HttpResponseMessage(HttpStatusCode.Accepted)
                {
                    Content = new StringContent(
                        JsonSerializer.Serialize(new { clarification = "What project is this for?" }),
                        Encoding.UTF8, "application/json")
                };
            }

            if (request.Method == HttpMethod.Post)
            {
                // Clarification response POST
                postRequest = request;
                return new HttpResponseMessage(HttpStatusCode.OK);
            }

            // Final GET poll: success
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    JsonSerializer.Serialize(new { auth_token = "clarified_tok", expires_in = 900 }),
                    Encoding.UTF8, "application/json")
            };
        });

        var client = new HttpClient(mockHandler);

        var result = await DeferredResponseLoop.PollAsync(
            client,
            "https://ps.example.com/pending/clarify1",
            new DeferredOptions
            {
                OnClarification = question =>
                {
                    receivedQuestion = question;
                    return Task.FromResult("Project Alpha");
                },
                MaxPollDurationSeconds = 10,
                PreferWaitSeconds = 0
            });

        Assert.Equal(HttpStatusCode.OK, result.Response.StatusCode);
        Assert.Equal("What project is this for?", receivedQuestion);
        Assert.NotNull(postRequest);
        Assert.Equal(HttpMethod.Post, postRequest!.Method);
    }

    // ──────────────────────────────────────────────────────────────
    // Test: Timeout throws TimeoutException
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task DeferredGrant_Timeout_ThrowsTimeoutException()
    {
        var mockHandler = new MockHttpHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.Accepted));

        var client = new HttpClient(mockHandler);

        await Assert.ThrowsAsync<TimeoutException>(() =>
            DeferredResponseLoop.PollAsync(
                client,
                "https://ps.example.com/pending/timeout1",
                new DeferredOptions
                {
                    MaxPollDurationSeconds = 1,
                    PreferWaitSeconds = 0
                }));
    }

    // ──────────────────────────────────────────────────────────────
    // Test: Error response (400) returns terminal DeferredResult with error
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task DeferredGrant_ErrorResponse_ReturnsDeferredResultWithError()
    {
        var mockHandler = new MockHttpHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.BadRequest)
            {
                Content = new StringContent(
                    JsonSerializer.Serialize(new { error = "invalid_scope", error_description = "scope not allowed" }),
                    Encoding.UTF8, "application/json")
            });

        var client = new HttpClient(mockHandler);

        var result = await DeferredResponseLoop.PollAsync(
            client,
            "https://ps.example.com/pending/err1",
            new DeferredOptions
            {
                MaxPollDurationSeconds = 10,
                PreferWaitSeconds = 0
            });

        Assert.Equal(HttpStatusCode.BadRequest, result.Response.StatusCode);
        Assert.NotNull(result.Error);
        Assert.Equal("invalid_scope", result.Error!.ErrorCode);
        Assert.Equal("scope not allowed", result.Error.ErrorDescription);
    }

    // ──────────────────────────────────────────────────────────────
    // Test: Prefer header is set with wait value
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task DeferredGrant_PreferHeader_SetsWaitValue()
    {
        HttpRequestMessage? capturedRequest = null;
        var mockHandler = new MockHttpHandler(request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    JsonSerializer.Serialize(new { auth_token = "tok", expires_in = 600 }),
                    Encoding.UTF8, "application/json")
            };
        });

        var client = new HttpClient(mockHandler);

        await DeferredResponseLoop.PollAsync(
            client,
            "https://ps.example.com/pending/pref1",
            new DeferredOptions
            {
                MaxPollDurationSeconds = 10,
                PreferWaitSeconds = 30
            });

        Assert.NotNull(capturedRequest);
        var preferValues = capturedRequest!.Headers.GetValues("Prefer").ToList();
        Assert.Contains("wait=30", preferValues);
    }

    // ──────────────────────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Mock HttpMessageHandler that delegates to a provided function.
    /// </summary>
    private sealed class MockHttpHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _handler;

        public MockHttpHandler(Func<HttpRequestMessage, HttpResponseMessage> handler)
        {
            _handler = handler;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(_handler(request));
        }
    }
}
