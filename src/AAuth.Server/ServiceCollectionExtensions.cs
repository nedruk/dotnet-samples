using AAuth.Core.Discovery;
using AAuth.Core.Signatures;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth.Server;

/// <summary>
/// Extension methods for registering AAuth server services.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds AAuth authentication to the service collection.
    /// </summary>
    public static AuthenticationBuilder AddAAuth(
        this AuthenticationBuilder builder,
        Action<AAuthServerOptions> configureServer,
        Action<AAuthAuthenticationSchemeOptions>? configureScheme = null)
    {
        return AddAAuth(builder, "AAuth", configureServer, configureScheme);
    }

    /// <summary>
    /// Adds AAuth authentication with a specific scheme name.
    /// </summary>
    public static AuthenticationBuilder AddAAuth(
        this AuthenticationBuilder builder,
        string scheme,
        Action<AAuthServerOptions> configureServer,
        Action<AAuthAuthenticationSchemeOptions>? configureScheme = null)
    {
        var serverOptions = new AAuthServerOptions
        {
            ServerIdentifier = null!,
            GetKeyMaterial = null!
        };
        configureServer(serverOptions);

        builder.Services.AddSingleton(serverOptions);
        builder.Services.AddSingleton(sp =>
        {
            var factory = sp.GetRequiredService<IHttpClientFactory>();
            return new IssuerKeyResolver(factory.CreateClient("__aauth_resolver__"));
        });
        builder.Services.AddSingleton<TokenVerifier>();
        builder.Services.AddSingleton<ResourceTokenFactory>();
        builder.Services.AddHttpClient("__aauth_resolver__");

        return builder.AddScheme<AAuthAuthenticationSchemeOptions, AAuthAuthenticationHandler>(
            scheme, configureScheme ?? (_ => { }));
    }
}
