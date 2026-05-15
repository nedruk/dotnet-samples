using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Core.Signatures;

/// <summary>
/// Result of verifying an HTTP Message Signature.
/// </summary>
public sealed record SignatureVerificationResult(
    bool IsValid,
    string? Thumbprint,
    SignatureKeyValue? SignatureKey,
    string? Error);

/// <summary>
/// Signs and verifies HTTP Message Signatures per the AAuth profile of RFC 9421.
/// </summary>
public static class HttpMessageSigner
{
    /// <summary>
    /// Sign an outgoing HTTP request. Adds Signature, Signature-Input, and Signature-Key headers.
    /// </summary>
    public static void Sign(
        HttpRequestMessage request,
        AsymmetricAlgorithm signingKey,
        SignatureKeyValue signatureKey,
        IReadOnlyList<string>? additionalComponents = null)
    {
        var signatureKeyHeaderValue = SignatureKeyHeader.Build(signatureKey);
        request.Headers.TryAddWithoutValidation("Signature-Key", signatureKeyHeaderValue);

        var created = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        // Collect header values for any additional components that are regular headers
        Dictionary<string, string>? headerValues = null;
        if (additionalComponents is { Count: > 0 })
        {
            headerValues = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var component in additionalComponents)
            {
                if (component.StartsWith('@')) continue; // derived components handled by SignatureBase

                if (request.Headers.TryGetValues(component, out var values))
                {
                    headerValues[component] = string.Join(", ", values);
                }
                else if (request.Content?.Headers.TryGetValues(component, out var contentValues) == true)
                {
                    headerValues[component] = string.Join(", ", contentValues);
                }
            }
        }

        var signatureBase = SignatureBase.Build(
            request.Method,
            request.RequestUri!,
            signatureKeyHeaderValue,
            headerValues,
            additionalComponents,
            created);

        var signatureBytes = SignData(signingKey, Encoding.UTF8.GetBytes(signatureBase));
        var signatureB64 = Convert.ToBase64String(signatureBytes);

        var components = SignatureBase.GetCoveredComponents(additionalComponents);
        var sigInput = new SignatureInput(components, created);

        request.Headers.TryAddWithoutValidation("Signature-Input", sigInput.Serialize());
        request.Headers.TryAddWithoutValidation("Signature", $"sig=:{signatureB64}:");
    }

    /// <summary>
    /// Verify an incoming HTTP request's signature. Returns verification result with the
    /// JWK Thumbprint of the signing key (needed for cnf binding checks).
    /// </summary>
    public static SignatureVerificationResult Verify(
        HttpRequestMessage request,
        JsonWebKey? signingPublicKey = null)
    {
        // Extract headers
        var signatureHeader = request.Headers.TryGetValues("Signature", out var sigValues)
            ? sigValues.FirstOrDefault() : null;
        var signatureInputHeader = request.Headers.TryGetValues("Signature-Input", out var siValues)
            ? siValues.FirstOrDefault() : null;
        var signatureKeyHeaderValue = request.Headers.TryGetValues("Signature-Key", out var skValues)
            ? skValues.FirstOrDefault() : null;

        if (string.IsNullOrEmpty(signatureHeader) ||
            string.IsNullOrEmpty(signatureInputHeader) ||
            string.IsNullOrEmpty(signatureKeyHeaderValue))
        {
            return new SignatureVerificationResult(false, null, null, "Missing signature headers");
        }

        SignatureKeyValue parsedSignatureKey;
        try
        {
            parsedSignatureKey = SignatureKeyHeader.Parse(signatureKeyHeaderValue);
        }
        catch (FormatException ex)
        {
            return new SignatureVerificationResult(false, null, null, $"Invalid Signature-Key: {ex.Message}");
        }

        // If no explicit public key provided, extract cnf.jwk from the JWT in Signature-Key
        if (signingPublicKey is null && parsedSignatureKey is SignatureKeyValue.Jwt jwtKey)
        {
            try
            {
                var handler = new Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler();
                var token = handler.ReadJsonWebToken(jwtKey.Token);
                var cnfClaim = token.GetClaim("cnf");
                var cnfDict = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, System.Text.Json.JsonElement>>(cnfClaim.Value)!;
                var jwkJson = cnfDict["jwk"].GetRawText();
                signingPublicKey = new JsonWebKey(jwkJson);
            }
            catch (Exception ex)
            {
                return new SignatureVerificationResult(false, null, parsedSignatureKey, $"Failed to extract cnf.jwk from token: {ex.Message}");
            }
        }

        if (signingPublicKey is null)
        {
            return new SignatureVerificationResult(false, null, parsedSignatureKey, "No signing public key available for verification");
        }

        SignatureInput sigInput;
        try
        {
            sigInput = SignatureInput.Parse(signatureInputHeader);
        }
        catch (FormatException ex)
        {
            return new SignatureVerificationResult(false, null, null, $"Invalid Signature-Input: {ex.Message}");
        }

        // Verify created timestamp is within window (60 seconds)
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (Math.Abs(now - sigInput.Created) > 60)
        {
            return new SignatureVerificationResult(false, null, parsedSignatureKey, "Signature timestamp outside validity window");
        }

        // Collect header values for verification
        var headerValues = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var component in sigInput.CoveredComponents)
        {
            if (component.StartsWith('@') || component == "signature-key") continue;

            if (request.Headers.TryGetValues(component, out var values))
            {
                headerValues[component] = string.Join(", ", values);
            }
            else if (request.Content?.Headers.TryGetValues(component, out var contentValues) == true)
            {
                headerValues[component] = string.Join(", ", contentValues);
            }
        }

        // Rebuild signature base
        var signatureBase = SignatureBase.Build(
            request.Method,
            request.RequestUri!,
            signatureKeyHeaderValue,
            headerValues.Count > 0 ? headerValues : null,
            sigInput.CoveredComponents.Where(c => c != "@method" && c != "@authority" && c != "@path" && c != "signature-key").ToList() is { Count: > 0 } extra ? extra : null,
            sigInput.Created);

        // Extract signature bytes
        var sigB64 = ExtractSignatureBytes(signatureHeader);
        if (sigB64 is null)
        {
            return new SignatureVerificationResult(false, null, parsedSignatureKey, "Invalid Signature header format");
        }

        var signatureBytes = Convert.FromBase64String(sigB64);
        var baseBytes = Encoding.UTF8.GetBytes(signatureBase);

        // Verify signature using the provided public key
        bool isValid;
        try
        {
            isValid = VerifyData(signingPublicKey, baseBytes, signatureBytes);
        }
        catch (Exception ex)
        {
            return new SignatureVerificationResult(false, null, parsedSignatureKey, $"Signature verification error: {ex.Message}");
        }

        if (!isValid)
        {
            return new SignatureVerificationResult(false, null, parsedSignatureKey, "Signature verification failed");
        }

        var thumbprint = JsonWebKeyThumbprint.Compute(signingPublicKey);
        return new SignatureVerificationResult(true, thumbprint, parsedSignatureKey, null);
    }

    private static byte[] SignData(AsymmetricAlgorithm key, byte[] data)
    {
        return key switch
        {
            ECDsa ecdsa => ecdsa.SignData(data, HashAlgorithmName.SHA256),
            _ => throw new NotSupportedException($"Unsupported key type: {key.GetType()}. Currently only ECDSA P-256 is supported.")
        };
    }

    private static bool VerifyData(JsonWebKey jwk, byte[] data, byte[] signature)
    {
        if (jwk.Kty == "EC" && jwk.Crv == "P-256")
        {
            using var ecdsa = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = Base64UrlEncoder.DecodeBytes(jwk.X),
                    Y = Base64UrlEncoder.DecodeBytes(jwk.Y)
                }
            });
            return ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256);
        }
        else
        {
            throw new NotSupportedException($"Unsupported key type: {jwk.Kty}/{jwk.Crv}. Currently only EC/P-256 is supported.");
        }
    }

    private static string? ExtractSignatureBytes(string signatureHeader)
    {
        // Format: sig=:base64:
        var start = signatureHeader.IndexOf(':');
        var end = signatureHeader.LastIndexOf(':');
        if (start < 0 || end <= start)
            return null;
        return signatureHeader[(start + 1)..end];
    }
}
