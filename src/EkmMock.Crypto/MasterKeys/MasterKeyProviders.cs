namespace EkmMock.Crypto;

/// <summary>Source of the Key Store Master Key. Injected so tests never touch environment variables.</summary>
public interface IMasterKeyProvider
{
    /// <exception cref="MasterKeyUnavailableException">No usable master key (the caller must refuse to start).</exception>
    MasterKey GetMasterKey();
}

/// <summary>A fixed key supplied by the caller (tests, embedding). The input bytes are copied.</summary>
public sealed class ExplicitMasterKeyProvider : IMasterKeyProvider
{
    private readonly byte[] _bytes;

    public ExplicitMasterKeyProvider(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != MasterKey.SizeBytes)
        {
            throw new ArgumentException($"Master key must be exactly {MasterKey.SizeBytes} bytes.", nameof(bytes));
        }

        _bytes = bytes.ToArray();
    }

    public MasterKey GetMasterKey() => MasterKey.FromBytes(_bytes, "explicit");
}

/// <summary>Explicit dev mode: a random key per process. Everything stored under it is unreadable after restart.</summary>
public sealed class ThrowAwayMasterKeyProvider : IMasterKeyProvider
{
    public MasterKey GetMasterKey() => MasterKey.CreateThrowAway();
}

/// <summary>Reads a base64 master key from a file (for example a Docker/Kubernetes secret).</summary>
public sealed class FileMasterKeyProvider : IMasterKeyProvider
{
    private readonly string _path;

    public FileMasterKeyProvider(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = path;
    }

    public MasterKey GetMasterKey()
    {
        string text;
        try
        {
            text = File.ReadAllText(_path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new MasterKeyUnavailableException("The master key file could not be read.");
        }

        return MasterKey.FromBase64(text, "file");
    }
}

/// <summary>
/// Spec 6.2: <c>EKMMOCK_MASTER_KEY</c> (base64) or <c>EKMMOCK_MASTER_KEY_FILE</c>. Missing refuses, unless
/// <c>devMode</c> is set, in which case a throw-away key is created and flagged. A configured but malformed key
/// is always an error, even in dev mode, so a misconfiguration is never silently masked.
/// </summary>
public sealed class EnvironmentMasterKeyProvider : IMasterKeyProvider
{
    public const string KeyVariable = "EKMMOCK_MASTER_KEY";
    public const string FileVariable = "EKMMOCK_MASTER_KEY_FILE";

    private readonly Func<string, string?> _getEnvironmentVariable;
    private readonly bool _devMode;

    public EnvironmentMasterKeyProvider(Func<string, string?>? getEnvironmentVariable = null, bool devMode = false)
    {
        _getEnvironmentVariable = getEnvironmentVariable ?? Environment.GetEnvironmentVariable;
        _devMode = devMode;
    }

    public MasterKey GetMasterKey()
    {
        var inline = _getEnvironmentVariable(KeyVariable);
        var file = _getEnvironmentVariable(FileVariable);
        var hasInline = !string.IsNullOrWhiteSpace(inline);
        var hasFile = !string.IsNullOrWhiteSpace(file);

        if (hasInline && hasFile)
        {
            throw new MasterKeyUnavailableException($"Both {KeyVariable} and {FileVariable} are set; set exactly one.");
        }

        if (hasInline)
        {
            return MasterKey.FromBase64(inline, $"environment:{KeyVariable}");
        }

        if (hasFile)
        {
            return new FileMasterKeyProvider(file!).GetMasterKey();
        }

        if (_devMode)
        {
            return MasterKey.CreateThrowAway();
        }

        throw new MasterKeyUnavailableException(
            $"No master key configured: set {KeyVariable} or {FileVariable} (or start in explicit dev mode).");
    }
}
