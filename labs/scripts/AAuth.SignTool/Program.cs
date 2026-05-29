using System.Security.Cryptography;
using System.Text.Json;
using AAuth.Core.Signatures;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

var options = CliOptions.Parse(args);
if (options.ShowHelp)
{
    CliOptions.PrintHelp();
    return 0;
}

try
{
    var request = new HttpRequestMessage(new HttpMethod(options.Method), options.Url);
    foreach (var header in options.Headers)
    {
        if (!request.Headers.TryAddWithoutValidation(header.Key, header.Value))
        {
            request.Content ??= new ByteArrayContent([]);
            if (!request.Content.Headers.TryAddWithoutValidation(header.Key, header.Value))
                throw new FormatException($"Failed to set header '{header.Key}'.");
        }
    }

    var keySourceJwt = options.KeyJwt ?? options.Jwt;
    using var signingKey = CreateSigningKeyFromJwt(keySourceJwt);
    HttpMessageSigner.Sign(
        request,
        signingKey,
        new SignatureKeyValue.Jwt(options.Jwt),
        options.Components.Count > 0 ? options.Components : null);

    Console.WriteLine($"Signature-Key: {GetRequiredHeader(request, "Signature-Key")}");
    Console.WriteLine($"Signature-Input: {GetRequiredHeader(request, "Signature-Input")}");
    Console.WriteLine($"Signature: {GetRequiredHeader(request, "Signature")}");
    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"error: {ex.Message}");
    return 1;
}

static string GetRequiredHeader(HttpRequestMessage request, string headerName)
{
    if (request.Headers.TryGetValues(headerName, out var values))
        return values.First();

    throw new InvalidOperationException($"Missing header '{headerName}' after signing.");
}

static AsymmetricAlgorithm CreateSigningKeyFromJwt(string jwt)
{
    var handler = new JsonWebTokenHandler();
    var token = handler.ReadJsonWebToken(jwt);

    if (!token.TryGetClaim("cnf", out var cnfClaim))
        throw new FormatException("JWT payload must contain cnf claim.");

    var cnf = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(cnfClaim.Value)
        ?? throw new FormatException("Invalid cnf claim.");

    if (!cnf.TryGetValue("jwk", out var jwkElement))
        throw new FormatException("JWT cnf claim must contain jwk.");

    var jwk = new JsonWebKey(jwkElement.GetRawText());

    if (string.Equals(jwk.Kty, "EC", StringComparison.Ordinal))
        return CreateEcSigningKey(jwk);

    if (string.Equals(jwk.Kty, "OKP", StringComparison.Ordinal))
        return CreateEd25519SigningKey(jwk);

    throw new NotSupportedException($"Unsupported JWK kty '{jwk.Kty}'.");
}

static AsymmetricAlgorithm CreateEcSigningKey(JsonWebKey jwk)
{
    if (!string.Equals(jwk.Crv, "P-256", StringComparison.Ordinal))
        throw new NotSupportedException($"Unsupported EC curve '{jwk.Crv}'. Expected P-256.");

    if (string.IsNullOrEmpty(jwk.D))
        throw new FormatException("EC JWK is missing private key parameter 'd'.");
    if (string.IsNullOrEmpty(jwk.X) || string.IsNullOrEmpty(jwk.Y))
        throw new FormatException("EC JWK must include public key coordinates 'x' and 'y'.");

    var d = Base64UrlEncoder.DecodeBytes(jwk.D);
    var x = Base64UrlEncoder.DecodeBytes(jwk.X);
    var y = Base64UrlEncoder.DecodeBytes(jwk.Y);

    return ECDsa.Create(new ECParameters
    {
        Curve = ECCurve.NamedCurves.nistP256,
        D = d,
        Q = new ECPoint { X = x, Y = y }
    });
}

static AsymmetricAlgorithm CreateEd25519SigningKey(JsonWebKey jwk)
{
    if (!string.Equals(jwk.Crv, "Ed25519", StringComparison.Ordinal))
        throw new NotSupportedException($"Unsupported OKP curve '{jwk.Crv}'. Expected Ed25519.");

    if (string.IsNullOrEmpty(jwk.D))
        throw new FormatException("OKP JWK is missing private key parameter 'd'.");

    var privateKeyBytes = Base64UrlEncoder.DecodeBytes(jwk.D);
    return Ed25519PrivateKey.FromPrivateKeyBytes(privateKeyBytes);
}

sealed class CliOptions
{
    public required string Jwt { get; init; }
    public string? KeyJwt { get; init; }
    public required string Method { get; init; }
    public required string Url { get; init; }
    public required IReadOnlyList<string> Components { get; init; }
    public required IReadOnlyDictionary<string, string> Headers { get; init; }
    public bool ShowHelp { get; init; }

    public static CliOptions Parse(string[] args)
    {
        var jwt = string.Empty;
        string? keyJwt = null;
        var method = string.Empty;
        var url = string.Empty;
        var showHelp = args.Length == 0;
        var components = new List<string>();
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        for (var i = 0; i < args.Length; i++)
        {
            var current = args[i];
            switch (current)
            {
                case "-h":
                case "--help":
                    showHelp = true;
                    break;
                case "--jwt":
                    jwt = ReadValue(args, ref i, "--jwt");
                    break;
                case "--key-jwt":
                    keyJwt = ReadValue(args, ref i, "--key-jwt");
                    break;
                case "--method":
                    method = ReadValue(args, ref i, "--method").ToUpperInvariant();
                    break;
                case "--url":
                    url = ReadValue(args, ref i, "--url");
                    break;
                case "--component":
                {
                    var component = ReadValue(args, ref i, "--component").Trim().ToLowerInvariant();
                    if (!string.IsNullOrWhiteSpace(component) &&
                        !components.Contains(component, StringComparer.OrdinalIgnoreCase))
                    {
                        components.Add(component);
                    }
                    break;
                }
                case "--header":
                {
                    var rawHeader = ReadValue(args, ref i, "--header");
                    var separator = rawHeader.IndexOf(':');
                    if (separator <= 0)
                        throw new FormatException($"Invalid --header value '{rawHeader}'. Use name:value.");

                    var name = rawHeader[..separator].Trim().ToLowerInvariant();
                    var value = rawHeader[(separator + 1)..].Trim();
                    if (string.IsNullOrEmpty(name))
                        throw new FormatException($"Invalid --header value '{rawHeader}'. Header name is required.");
                    headers[name] = value;
                    break;
                }
                default:
                    throw new FormatException($"Unknown argument '{current}'. Use --help for usage.");
            }
        }

        if (!showHelp)
        {
            if (string.IsNullOrWhiteSpace(jwt))
                throw new FormatException("Missing required --jwt argument.");
            if (string.IsNullOrWhiteSpace(method))
                throw new FormatException("Missing required --method argument.");
            if (!Uri.TryCreate(url, UriKind.Absolute, out _))
                throw new FormatException("Missing or invalid --url argument. Expected absolute URL.");
        }

        return new CliOptions
        {
            Jwt = jwt,
            KeyJwt = keyJwt,
            Method = method,
            Url = url,
            Components = components,
            Headers = headers,
            ShowHelp = showHelp
        };
    }

    public static void PrintHelp()
    {
        Console.WriteLine("Generate AAuth HTTP Signature headers using existing .NET implementation.");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  dotnet run --project labs/scripts/AAuth.SignTool -- --jwt <JWT> --method <METHOD> --url <URL> [options]");
        Console.WriteLine();
        Console.WriteLine("Options:");
        Console.WriteLine("  --key-jwt <JWT>      JWT containing the private signing key (cnf.jwk.d).");
        Console.WriteLine("                       Use when --jwt holds a token whose cnf.jwk has no private key");
        Console.WriteLine("                       (e.g. auth tokens issued by a Person Server).");
        Console.WriteLine("  --component <name>   Additional covered component (repeatable), e.g. authorization");
        Console.WriteLine("  --header <name:val>  Header value used for signing of additional components (repeatable)");
        Console.WriteLine("  -h, --help           Show this help");
    }

    private static string ReadValue(string[] args, ref int index, string optionName)
    {
        if (index + 1 >= args.Length)
            throw new FormatException($"Missing value for {optionName}.");

        index++;
        return args[index];
    }
}
