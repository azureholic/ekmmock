using Azure.Core;
using Azure.Identity;

namespace EkmMock.Cli.ConsoleApi;

/// <summary>The Entra app registration of an <c>EntraId</c> console, as the CLI needs it for the device-code sign-in.</summary>
internal sealed record EntraSettings(string TenantId, string ClientId, string Scope)
{
    public static string DefaultScope(string clientId) => $"api://{clientId}/.default";
}

internal enum ConsoleAuthMode
{
    /// <summary>Token from <c>EKMMOCK_CONSOLE_TOKEN</c> if set, else device-code sign-in when tenant and client id are known, else none (LoopbackOnly console).</summary>
    Auto,

    /// <summary>No sign-in: only the <c>X-EkmMock-Client</c> header (a <c>LoopbackOnly</c> console).</summary>
    Loopback,

    /// <summary>Entra device-code sign-in (needs tenant and client id).</summary>
    Entra,
}

/// <summary>Gives the bearer token for a console call, or null when the console needs none.</summary>
internal interface ITokenSource
{
    ValueTask<string?> GetTokenAsync(CancellationToken cancellationToken);
}

internal sealed class StaticTokenSource : ITokenSource
{
    private readonly string _token;

    public StaticTokenSource(string token)
    {
        _token = token;
    }

    public ValueTask<string?> GetTokenAsync(CancellationToken cancellationToken) => ValueTask.FromResult<string?>(_token);
}

/// <summary>
/// The device-code sign-in: asks the credential for a token (which prints the "go to https://microsoft.com/devicelogin and enter the code" message through the callback) and keeps the token <b>in memory
/// only</b> until shortly before it expires. Nothing is written to disk: there is no token cache file, so closing the terminal ends the session.
/// </summary>
internal sealed class CredentialTokenSource : ITokenSource
{
    private static readonly TimeSpan Margin = TimeSpan.FromMinutes(2);

    private readonly TokenCredential _credential;
    private readonly string[] _scopes;
    private readonly TimeProvider _time;
    private AccessToken? _cached;

    public CredentialTokenSource(TokenCredential credential, string scope, TimeProvider time)
    {
        _credential = credential;
        _scopes = [scope];
        _time = time;
    }

    public async ValueTask<string?> GetTokenAsync(CancellationToken cancellationToken)
    {
        if (_cached is { } cached && cached.ExpiresOn - _time.GetUtcNow() > Margin)
        {
            return cached.Token;
        }

        try
        {
            _cached = await _credential.GetTokenAsync(new TokenRequestContext(_scopes), cancellationToken).ConfigureAwait(false);
        }
        catch (CredentialUnavailableException exception)
        {
            throw CliException.Connection("Entra sign-in is not available: " + FirstLine(exception.Message), exception);
        }
        catch (AuthenticationFailedException exception)
        {
            // The message of the sign-in library is useful (consent missing, wrong tenant) and contains no token.
            throw CliException.Connection("Entra sign-in failed: " + FirstLine(exception.Message), exception);
        }

        return _cached.Value.Token;
    }

    private static string FirstLine(string text)
    {
        var end = text.IndexOfAny(['\r', '\n']);
        return end < 0 ? text : text[..end];
    }

    /// <summary>The production credential: <c>DeviceCodeCredential</c> against the given tenant and public client app, printing the code message through <paramref name="prompt"/>.</summary>
    public static TokenCredential CreateDeviceCodeCredential(EntraSettings settings, Action<string> prompt)
        => new DeviceCodeCredential(new DeviceCodeCredentialOptions
        {
            TenantId = settings.TenantId,
            ClientId = settings.ClientId,
            DeviceCodeCallback = (info, _) =>
            {
                prompt(info.Message);
                return Task.CompletedTask;
            },
        });
}
