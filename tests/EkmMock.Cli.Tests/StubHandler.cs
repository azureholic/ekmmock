using System.Net;
using System.Text;
using Azure.Core;

namespace EkmMock.Cli.Tests;

/// <summary>A scripted HTTP handler for the console client tests: records every request and answers with whatever the test says.</summary>
internal sealed class StubHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, HttpResponseMessage> _respond;

    public StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond)
    {
        _respond = respond;
    }

    public List<RecordedRequest> Requests { get; } = [];

    public static HttpResponseMessage Json(int status, string body) => new((HttpStatusCode)status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
        Requests.Add(new RecordedRequest(request.Method.Method, request.RequestUri!.PathAndQuery, request.Headers.ToDictionary(static h => h.Key, static h => string.Join(",", h.Value), StringComparer.OrdinalIgnoreCase), body));
        return _respond(request);
    }
}

internal sealed record RecordedRequest(string Method, string Path, Dictionary<string, string> Headers, string? Body);

/// <summary>A fake sign-in: hands out a fixed token and counts how often it was asked (device-code flow without a tenant).</summary>
internal sealed class FakeCredential : TokenCredential
{
    private readonly string _token;
    private readonly Action? _onPrompt;

    public FakeCredential(string token, Action? onPrompt = null)
    {
        _token = token;
        _onPrompt = onPrompt;
    }

    public int Calls { get; private set; }

    public List<string[]> Scopes { get; } = [];

    public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) => Issue(requestContext);

    public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken) => ValueTask.FromResult(Issue(requestContext));

    private AccessToken Issue(TokenRequestContext context)
    {
        Calls++;
        Scopes.Add(context.Scopes);
        _onPrompt?.Invoke();
        return new AccessToken(_token, DateTimeOffset.UtcNow.AddHours(1));
    }
}
