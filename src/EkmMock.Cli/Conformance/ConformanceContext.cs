using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using EkmMock.Cli.ConsoleApi;
using EkmMock.Cli.Ekm;
using EkmMock.Cli.Infrastructure;

namespace EkmMock.Cli.Conformance;

/// <summary>Everything the user gave to <c>ekmmock test conformance</c>.</summary>
internal sealed class ConformanceOptions
{
    public required EkmTarget Target { get; init; }

    public required ClientIdentity Client { get; init; }

    public ClientIdentity? AltClient { get; init; }

    public ClientIdentity? RogueClient { get; init; }

    public X509Certificate2Collection? Roots { get; init; }

    public ConsoleSettings? Console { get; init; }

    /// <summary>The namespace of <see cref="EkmTarget.Prefix"/>; resolved through the console when not given.</summary>
    public string? Namespace { get; init; }

    /// <summary>Existing keys used when no console is given (they must be AES-256 and RSA): the sample keys of <c>--dev</c> by default.</summary>
    public string AesKey { get; init; } = "aes-key-1";

    public string RsaKey { get; init; } = "rsa-key-1";

    /// <summary>A second server certificate for the same host and CA (PEM files), uploaded through the console by the certificate reload test.</summary>
    public string? ReplacementCertFile { get; init; }

    public string? ReplacementKeyFile { get; init; }

    public bool AllowDisruptive { get; init; }

    public string? PersistenceState { get; init; }

    public string? Only { get; init; }

    public string ReportPath { get; init; } = "conformance-report.json";

    public string RunId { get; init; } = Convert.ToHexString(RandomNumberGenerator.GetBytes(4)).ToLowerInvariant();
}

/// <summary>A key the suite uses: either one it created for this run (<see cref="Temporary"/>, destroyed at the end) or an existing one named on the command line.</summary>
internal sealed record SuiteKey(string Namespace, string Name, bool IsRsa, int Size, bool Temporary)
{
    public string Alg => IsRsa ? "RSA-OAEP-256" : "A256KWP";
}

/// <summary>
/// The shared state of one conformance run: the clients, the console connection, the temporary keys and namespaces (created on first use, destroyed at the end), the cleanup list and the secrets
/// the run used (for the leak scan, kept in memory only). Everything it creates carries <c>conf-{runId}</c> in its name.
/// </summary>
internal sealed class ConformanceContext : IAsyncDisposable
{
    private readonly Dictionary<string, Task<SuiteKey>> _keys = [];
    private readonly Dictionary<string, Task<TempNamespace>> _namespaces = [];
    private readonly List<(string Namespace, string Name)> _createdKeys = [];
    private readonly List<string> _createdNamespaces = [];
    private readonly List<string> _createdFaults = [];
    private readonly List<byte[]> _secrets = [];
    private readonly object _gate = new();
    private Task<string>? _targetNamespace;
    private Task<AboutInfo>? _about;
    private Task<ConsoleStatus>? _status;
    private Task<FaultList>? _faults;
    private bool _disposed;

    public ConformanceContext(ConformanceOptions options, CliEnvironment env)
    {
        Options = options;
        Env = env;
        Ekm = EkmClient.Create(options.Target, options.Client, options.Roots, options.RunId);
        if (options.Console is not null)
        {
            Console = ConsoleApiClient.Create(options.Console, env);
        }
    }

    public ConformanceOptions Options { get; }

    public CliEnvironment Env { get; }

    public EkmClient Ekm { get; }

    public ConsoleApiClient? Console { get; }

    public string RunId => Options.RunId;

    public IReadOnlyList<byte[]> Secrets
    {
        get
        {
            lock (_gate)
            {
                return [.. _secrets];
            }
        }
    }

    public List<string> Destroyed { get; } = [];

    public List<string> Leftover { get; } = [];

    public string Name(string suffix) => $"conf-{RunId}-{suffix}";

    // ---- secrets ----

    /// <summary>Random synthetic bytes (a DEK, a KEK); remembered so that the leak scan can look for them.</summary>
    public byte[] Random(int length)
    {
        var bytes = RandomNumberGenerator.GetBytes(length);
        Remember(bytes);
        return bytes;
    }

    public void Remember(byte[] secret)
    {
        lock (_gate)
        {
            _secrets.Add(secret);
        }
    }

    // ---- console ----

    public ConsoleApiClient RequireConsole(string why)
        => Console ?? throw new SkipTest($"needs --console ({why})");

    public Task<AboutInfo> AboutAsync(CancellationToken ct) => _about ??= RequireConsole("server configuration").AboutAsync(ct);

    public Task<ConsoleStatus> StatusAsync(CancellationToken ct) => _status ??= RequireConsole("server status").StatusAsync(ct);

    public Task<FaultList> FaultsAsync(CancellationToken ct) => _faults ??= RequireConsole("fault injection").ListFaultsAsync(ct);

    /// <summary>Skips unless the server has fault injection switched on (<c>EKMMOCK_ENABLE_FAULTS=true</c>).</summary>
    public async Task RequireFaultsAsync(CancellationToken ct)
    {
        var faults = await FaultsAsync(ct).ConfigureAwait(false);
        if (!faults.Enabled)
        {
            throw new SkipTest("fault injection is disabled on the server (start it with EKMMOCK_ENABLE_FAULTS=true)");
        }
    }

    /// <summary>Skips unless key import is switched on (<c>EKMMOCK_ALLOW_KEY_IMPORT=true</c>).</summary>
    public async Task RequireImportAsync(CancellationToken ct)
    {
        var about = await AboutAsync(ct).ConfigureAwait(false);
        if (!about.KeyImportEnabled)
        {
            throw new SkipTest("key import is switched off on the server (start it with EKMMOCK_ALLOW_KEY_IMPORT=true to import test vectors)");
        }
    }

    /// <summary>Name of the namespace the <c>--url</c> prefix belongs to.</summary>
    public Task<string> TargetNamespaceAsync(CancellationToken ct) => _targetNamespace ??= ResolveNamespaceAsync(ct);

    private async Task<string> ResolveNamespaceAsync(CancellationToken ct)
    {
        if (Options.Namespace is { Length: > 0 } given)
        {
            return given;
        }

        var console = RequireConsole("to find the namespace of the URL prefix; or pass --namespace");
        var namespaces = await console.ListNamespacesAsync(ct).ConfigureAwait(false);
        var match = namespaces.FirstOrDefault(n => string.Equals(n.Prefix, Options.Target.Prefix, StringComparison.Ordinal))
            ?? throw new TestFailure($"setup: the console has no namespace with the path prefix '{Options.Target.Prefix}' of --url (namespaces: {string.Join(", ", namespaces.Select(n => n.Name))}). Is --console the console of this server?");
        return match.Name;
    }

    // ---- keys ----

    /// <summary>The AES-256 key of the run: a temporary one with a console, otherwise <c>--aes-key</c>.</summary>
    public Task<SuiteKey> AesKeyAsync(CancellationToken ct) => KeyAsync("aes", isRsa: false, 256, ct);

    /// <summary>An RSA key of the given size: temporary with a console; without one only <c>--rsa-key</c> (whatever size it has) is available and other sizes skip.</summary>
    public Task<SuiteKey> RsaKeyAsync(int size, CancellationToken ct) => KeyAsync("rsa" + size, isRsa: true, size, ct);

    public IReadOnlyList<int> RsaSizes => Console is null ? [2048] : [2048, 3072, 4096];

    private Task<SuiteKey> KeyAsync(string suffix, bool isRsa, int size, CancellationToken ct)
    {
        lock (_gate)
        {
            if (!_keys.TryGetValue(suffix, out var task))
            {
                task = ProvisionAsync(suffix, isRsa, size, ct);
                _keys[suffix] = task;
            }

            return task;
        }
    }

    private async Task<SuiteKey> ProvisionAsync(string suffix, bool isRsa, int size, CancellationToken ct)
    {
        if (Console is null)
        {
            var existing = isRsa ? Options.RsaKey : Options.AesKey;
            var metadata = await Ekm.MetadataAsync(existing, ct).ConfigureAwait(false);
            if (metadata.Status != 200)
            {
                throw new TestFailure($"setup: the key '{existing}' ({(isRsa ? "--rsa-key" : "--aes-key")}) is not usable: {Expect.Describe(metadata)}. Create it (ekmmock key create) or pass --console so that the suite creates its own keys.");
            }

            var actualSize = metadata.GetKeySize();
            if ((isRsa && actualSize != size) || (!isRsa && metadata.GetString("key_type") != "oct"))
            {
                throw new SkipTest($"needs --console to create an {(isRsa ? $"RSA-{size}" : "AES-256")} key (the existing key '{existing}' is {metadata.GetString("key_type")} {actualSize})");
            }

            return new SuiteKey(await SafeNamespaceAsync(ct).ConfigureAwait(false), existing, isRsa, actualSize, Temporary: false);
        }

        var ns = await TargetNamespaceAsync(ct).ConfigureAwait(false);
        var name = Name(suffix);
        await Console.CreateKeyAsync(new CreateKeyBody(ns, name, isRsa ? "rsa" : "aes", size, AllowReuseOfDestroyedName: false), ct).ConfigureAwait(false);
        lock (_gate)
        {
            _createdKeys.Add((ns, name));
        }

        return new SuiteKey(ns, name, isRsa, size, Temporary: true);
    }

    private async Task<string> SafeNamespaceAsync(CancellationToken ct)
    {
        try
        {
            return await TargetNamespaceAsync(ct).ConfigureAwait(false);
        }
        catch (SkipTest)
        {
            return Options.Namespace ?? "_default";
        }
    }

    /// <summary>Creates an extra key in the target namespace (a disabled/expired/destroyed key must be a key of its own).</summary>
    public async Task<SuiteKey> CreateExtraKeyAsync(string suffix, bool isRsa, CancellationToken ct)
    {
        var console = RequireConsole("to create a key for this check");
        var ns = await TargetNamespaceAsync(ct).ConfigureAwait(false);
        var name = Name(suffix);
        await console.CreateKeyAsync(new CreateKeyBody(ns, name, isRsa ? "rsa" : "aes", isRsa ? 2048 : 256, AllowReuseOfDestroyedName: false), ct).ConfigureAwait(false);
        lock (_gate)
        {
            _createdKeys.Add((ns, name));
        }

        return new SuiteKey(ns, name, isRsa, isRsa ? 2048 : 256, Temporary: true);
    }

    /// <summary>Imports a key the client knows the material of (RFC vectors, an RSA key it can decrypt with). The material goes to the server only, never to a log or the report.</summary>
    public async Task<SuiteKey> ImportKeyAsync(string suffix, bool isRsa, string material, CancellationToken ct)
    {
        var console = RequireConsole("key import");
        await RequireImportAsync(ct).ConfigureAwait(false);
        var ns = await TargetNamespaceAsync(ct).ConfigureAwait(false);
        var name = Name(suffix);
        var view = await console.ImportKeyAsync(new ImportKeyBody(ns, name, isRsa ? "rsa" : "aes", material, AllowReuseOfDestroyedName: false), ct).ConfigureAwait(false);
        lock (_gate)
        {
            _createdKeys.Add((ns, name));
        }

        return new SuiteKey(ns, name, isRsa, view.Size, Temporary: true);
    }

    public void ForgetKey(SuiteKey key)
    {
        lock (_gate)
        {
            _createdKeys.Remove((key.Namespace, key.Name));
        }
    }

    // ---- namespaces ----

    /// <summary>A second namespace with its own path prefix. <paramref name="sameTrust"/> true trusts the same clients as the target (so the main client certificate is authorized there); false trusts only another CN.</summary>
    public Task<TempNamespace> OtherNamespaceAsync(bool sameTrust, CancellationToken ct)
    {
        lock (_gate)
        {
            var kind = sameTrust ? "same" : "othercn";
            if (!_namespaces.TryGetValue(kind, out var task))
            {
                task = CreateNamespaceAsync(kind, sameTrust, ct);
                _namespaces[kind] = task;
            }

            return task;
        }
    }

    private async Task<TempNamespace> CreateNamespaceAsync(string kind, bool sameTrust, CancellationToken ct)
    {
        var console = RequireConsole("to create a second namespace");
        var target = await console.GetNamespaceAsync(await TargetNamespaceAsync(ct).ConfigureAwait(false), ct).ConfigureAwait(false);
        if (target.CaCertificates.Count == 0)
        {
            throw new TestFailure("setup: the target namespace trusts no CA, so its trust cannot be copied to a second namespace");
        }

        var name = Name("ns-" + kind);
        var prefix = name;
        var cns = sameTrust ? target.SubjectCommonNames : ["conformance-other-client.invalid"];
        await console.CreateNamespaceAsync(new NamespaceBody(name, prefix, cns, [.. target.CaCertificates.Select(static c => c.DerBase64)]), ct).ConfigureAwait(false);
        lock (_gate)
        {
            _createdNamespaces.Add(name);
        }

        return new TempNamespace(name, prefix);
    }

    // ---- faults ----

    public void TrackFault(string id)
    {
        lock (_gate)
        {
            _createdFaults.Add(id);
        }
    }

    public async Task RemoveFaultAsync(string id)
    {
        try
        {
            await Console!.DeleteFaultAsync(id, CancellationToken.None).ConfigureAwait(false);
        }
        catch (ConsoleApiException exception) when (exception.Status == 404)
        {
            // Already gone (expired or cleared).
        }

        lock (_gate)
        {
            _createdFaults.Remove(id);
        }
    }

    // ---- TLS variants ----

    /// <summary>A client of the same endpoint with another protocol set and/or certificate (the TLS and trust checks).</summary>
    public EkmClient CreateVariantClient(ClientIdentity? identity, System.Security.Authentication.SslProtocols protocols = System.Security.Authentication.SslProtocols.Tls13, int maxConnections = 4, TimeSpan? timeout = null)
        => EkmClient.Create(Options.Target, identity, Options.Roots, RunId, protocols, maxConnections, timeout);

    // ---- cleanup ----

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (Console is not null)
        {
            string[] faults;
            (string Namespace, string Name)[] keys;
            string[] namespaces;
            lock (_gate)
            {
                faults = [.. _createdFaults];
                keys = [.. _createdKeys];
                namespaces = [.. _createdNamespaces];
            }

            foreach (var id in faults)
            {
                try
                {
                    await Console.DeleteFaultAsync(id, CancellationToken.None).ConfigureAwait(false);
                }
                catch (Exception exception) when (exception is ConsoleApiException or CliException)
                {
                    Leftover.Add($"fault rule {id}: {exception.Message}");
                }
            }

            foreach (var (ns, name) in keys)
            {
                try
                {
                    await Console.DestroyKeyAsync(ns, name, name, CancellationToken.None).ConfigureAwait(false);
                    Destroyed.Add($"key {ns}/{name}");
                }
                catch (Exception exception) when (exception is ConsoleApiException or CliException)
                {
                    // A key that was already destroyed by a check (the destroyed-key test) is not left over.
                    if (exception is ConsoleApiException { Status: 409 })
                    {
                        Destroyed.Add($"key {ns}/{name}");
                    }
                    else
                    {
                        Leftover.Add($"key {ns}/{name}: {exception.Message}");
                    }
                }
            }

            foreach (var name in namespaces)
            {
                try
                {
                    await Console.DeleteNamespaceAsync(name, new DeleteNamespaceBody(name, DestroyKeys: true), CancellationToken.None).ConfigureAwait(false);
                    Destroyed.Add($"namespace {name}");
                }
                catch (Exception exception) when (exception is ConsoleApiException or CliException)
                {
                    Leftover.Add($"namespace {name}: {exception.Message}");
                }
            }
        }

        Ekm.Dispose();
        Console?.Dispose();
    }
}

internal sealed record TempNamespace(string Name, string Prefix);

internal static class EkmReplyExtensions
{
    /// <summary>The <c>key_size</c> of a metadata answer, or 0.</summary>
    public static int GetKeySize(this EkmReply reply)
    {
        using var json = reply.TryJson();
        return json is { RootElement.ValueKind: System.Text.Json.JsonValueKind.Object } && json.RootElement.TryGetProperty("key_size", out var size) && size.TryGetInt32(out var value) ? value : 0;
    }
}
