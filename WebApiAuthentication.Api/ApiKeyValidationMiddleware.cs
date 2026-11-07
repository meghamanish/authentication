using System.Diagnostics;

namespace WebApiAuthentication.Api
{
    public class ApiKeyValidationMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<ApiKeyValidationMiddleware> _logger;

        public ApiKeyValidationMiddleware(RequestDelegate next, ILogger<ApiKeyValidationMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var sw = Stopwatch.StartNew();

            var config = context.RequestServices.GetRequiredService<IConfiguration>();
            var validApiKey = config.GetValue<string>("Authentication:ApiKey"); // config.GetSection("Authentication:ApiKey").Value;

            // Before next middleware
            _logger.LogInformation("Middleware start: {Method} {Path}", context.Request.Method, context.Request.Path);

            try
            {
                if (string.IsNullOrEmpty(validApiKey))
                {
                    throw new KeyNotFoundException("ApiKey not found in configuration");
                }

                //HttpContext.Request.Headers["X-ApiKey"];
                if (!context.Request.Headers.TryGetValue("X-ApiKey", out var extractedApiKey))
                {
                    if (!context.Request.Query.TryGetValue("X-ApiKey", out extractedApiKey))
                    {
                        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                        await context.Response.WriteAsync("Invalid ApiKey provided.");
                        return;
                    }
                }

                if (!extractedApiKey.Equals(validApiKey))
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    await context.Response.WriteAsync("No ApiKey provided.");
                    return;
                }
                await _next(context);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unhandled exception in CustomMiddleware");
                throw;
            }
            finally
            {
                sw.Stop();
                // After next middleware
                _logger.LogInformation(
                    "Middleware end: {Method} {Path} => {StatusCode} in {ElapsedMs}ms",
                    context.Request.Method,
                    context.Request.Path,
                    context.Response.StatusCode,
                    sw.ElapsedMilliseconds);
            }
        }
    }
}
