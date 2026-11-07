using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using WebApiAuthentication.Api.Utilities;

namespace WebApiAuthentication.Api;

[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class)]
public sealed class ApiKeyValidationAuthorizationFilter : Attribute, IAuthorizationFilter
{
    public void OnAuthorization(AuthorizationFilterContext context)
    {
        if (!IsValidApiKey(context))
        {
            context.Result = new UnauthorizedResult();
        }
    }
        
    private static bool IsValidApiKey(AuthorizationFilterContext context)
    {
        var services = context.HttpContext.RequestServices;
        var config = services.GetRequiredService<IConfiguration>();
        var encryption = services.GetRequiredService<IEncryption>();

        var storedApiKeyHash = config.GetValue<string>("Authentication:ApiKeyHash");
        if (string.IsNullOrWhiteSpace(storedApiKeyHash))
        {
            throw new KeyNotFoundException("ApiKey hash not found in configuration");
        }

        if (!context.HttpContext.Request.Headers.TryGetValue("X-ApiKey", out var extractedApiKey)
            && !context.HttpContext.Request.Query.TryGetValue("X-ApiKey", out extractedApiKey))
        {
            return false;
        }

        var providedApiKey = extractedApiKey.ToString();
        if (string.IsNullOrWhiteSpace(providedApiKey))
        {
            return false;
        }

        var providedHash = encryption.GetHash(providedApiKey);
        return string.Equals(providedHash, storedApiKeyHash, StringComparison.Ordinal);
    }
}
