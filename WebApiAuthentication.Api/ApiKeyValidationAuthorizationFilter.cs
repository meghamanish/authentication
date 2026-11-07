using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System.Diagnostics;

namespace WebApiAuthentication.Api;

[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class)]
public class ApiKeyValidationAuthorizationFilter : Attribute, IAuthorizationFilter
{
    public void OnAuthorization(AuthorizationFilterContext context)
    {
        if (!IsValidApiKey(context))
        {
            context.Result = new UnauthorizedResult();
        }
    }

    private bool IsValidApiKey(AuthorizationFilterContext context)
    {
        var config = context.HttpContext.RequestServices.GetRequiredService<IConfiguration>();
        var validApiKey = config.GetValue<string>("Authentication:ApiKey");

        if (string.IsNullOrEmpty(validApiKey))
        {
            throw new KeyNotFoundException("ApiKey not found in configuration");
        }

        if (!context.HttpContext.Request.Headers.TryGetValue("X-ApiKey", out var extractedApiKey))
        {
            if (!context.HttpContext.Request.Query.TryGetValue("X-ApiKey", out extractedApiKey))
            {
                return false;
            }
        }

        return true;
    }
}
