using AAuth.Core.Discovery;
using AAuth.Core.Signatures;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth.Agent;

/// <summary>
/// Extension methods for registering AAuth agent services.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds an AAuth-authenticated HttpClient to the service collection.
    /// </summary>
    public static IHttpClientBuilder AddAAuthAgent(
        this IServiceCollection services,
        string httpClientName,
        Action<AAuthAgentOptions> configure)
    {
        services.AddSingleton(sp =>
        {
            var httpClient = sp.GetRequiredService<IHttpClientFactory>().CreateClient("__aauth_resolver__");
            return new IssuerKeyResolver(httpClient);
        });

        return services.AddHttpClient(httpClientName)
            .AddHttpMessageHandler(sp =>
            {
                var options = new AAuthAgentOptions { GetKeyMaterial = null! };
                configure(options);
                var resolver = sp.GetRequiredService<IssuerKeyResolver>();
                return new AAuthDelegatingHandler(options, resolver);
            });
    }
}
