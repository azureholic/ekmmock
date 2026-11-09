#pragma warning disable xUnit1051 // The console tests use HttpClients with a bounded timeout; they do not need per-call cancellation tokens.

using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace EkmMock.Server.Tests;

/// <summary>An answer of <c>/api/console</c>: status, body text and the JSON view of it.</summary>
internal sealed record ApiReply(HttpStatusCode Status, string Text, string? ContentType, HttpResponseHeaders Headers)
{
    public int StatusCode => (int)Status;

    public JsonDocument Json() => JsonDocument.Parse(Text);

    /// <summary>The <c>code</c> of an error body (<c>{"code":"...","message":"..."}</c>).</summary>
    public string ErrorCode => Json().RootElement.TryGetProperty("code", out var code) ? code.GetString() ?? string.Empty : string.Empty;

    public string ErrorMessage => Json().RootElement.TryGetProperty("message", out var message) ? message.GetString() ?? string.Empty : string.Empty;

    public JsonElement Root => Json().RootElement;
}

/// <summary>
/// A scripted client of the console REST API, the way the CLI will call it: JSON snake_case bodies, the <c>X-EkmMock-Client</c> header as the CSRF proof of a non-browser client
/// (switch it off with <c>cli: false</c> to prove what happens without it).
/// </summary>
internal sealed class AdminApi
{
    public static readonly JsonSerializerOptions Snake = new() { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower, DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull };

    private readonly HttpClient _http;

    public AdminApi(HttpClient http)
    {
        _http = http;
    }

    public HttpClient Http => _http;

    public Task<ApiReply> GetAsync(string path, Action<HttpRequestMessage>? configure = null) => SendAsync(HttpMethod.Get, path, null, configure, cli: false);

    public Task<ApiReply> PostAsync(string path, object? body = null, Action<HttpRequestMessage>? configure = null, bool cli = true) => SendAsync(HttpMethod.Post, path, body ?? new { }, configure, cli);

    public Task<ApiReply> PutAsync(string path, object? body = null, Action<HttpRequestMessage>? configure = null, bool cli = true) => SendAsync(HttpMethod.Put, path, body ?? new { }, configure, cli);

    public async Task<ApiReply> SendAsync(HttpMethod method, string path, object? body, Action<HttpRequestMessage>? configure = null, bool cli = true)
    {
        using var request = new HttpRequestMessage(method, path);
        if (cli)
        {
            request.Headers.Add("X-EkmMock-Client", "tests/1.0");
        }

        if (body is not null)
        {
            request.Content = new StringContent(body is string text ? text : JsonSerializer.Serialize(body, Snake), Encoding.UTF8, "application/json");
        }

        configure?.Invoke(request);
        using var response = await _http.SendAsync(request);
        return new ApiReply(response.StatusCode, await response.Content.ReadAsStringAsync(), response.Content.Headers.ContentType?.MediaType, response.Headers);
    }
}
