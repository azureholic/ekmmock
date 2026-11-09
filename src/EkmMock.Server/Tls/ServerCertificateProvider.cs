using EkmMock.Pki;
using EkmMock.Server.Hosting;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.Tls;

/// <summary>The current server certificate and what the console needs to show about it (spec 5.3).</summary>
internal interface IServerCertificateProvider
{
    /// <summary>The certificate new connections are served. Never null once the provider exists; swapped atomically on reload.</summary>
    ServerCertificateSnapshot Current { get; }

    ServerCertificateInfo Info { get; }

    /// <summary>The last reload or upload failure, or null when the last attempt succeeded. The served certificate is unaffected by a failure.</summary>
    (string Message, DateTimeOffset AtUtc)? LastError { get; }

    /// <summary>
    /// Validates a PEM chain and key and, if valid, serves it for new connections and persists it to <c>Tls:CertFile</c>/<c>Tls:KeyFile</c>
    /// when those are configured. Existing connections are not touched. Throws <see cref="ServerCertificateException"/> and keeps
    /// the current certificate when the input is not usable. This is the seam for the console upload (M6).
    /// </summary>
    Task<ServerCertificateInfo> ReplaceAsync(string certificatePem, string privateKeyPem, CancellationToken cancellationToken = default, ServerCertificateSource source = ServerCertificateSource.Uploaded);

    /// <summary>Dev mode only: the PEM (public) of the generated root CA behind the generated localhost certificate, null otherwise.</summary>
    string? DevelopmentRootCaPem { get; }

    event Action<ServerCertificateSnapshot>? Changed;
}

/// <summary>
/// The hot-reloadable server certificate (spec 5.3). Files are watched (<see cref="FileSystemWatcher"/>, debounced) and polled
/// (default every 60 s) as a fallback for volume mounts and symlink swaps that raise no events. A new certificate is fully loaded
/// and validated off to the side and then swapped in with one volatile write: connections in progress and handshakes that already picked
/// the old certificate are never disturbed, and new connections get the new one. A file that is missing, half-written, mismatched or
/// expired is rejected: the old certificate keeps serving, a warning is logged and <see cref="LastError"/> says why.
/// </summary>
internal sealed class ServerCertificateProvider : IServerCertificateProvider, IDisposable
{
    private readonly TlsOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger<ServerCertificateProvider> _logger;
    private readonly object _gate = new();
    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly Timer? _pollTimer;
    private readonly Timer? _debounceTimer;

    // Where the console persists an uploaded or generated certificate when no Tls:CertFile/KeyFile is configured: <Data:Path>/tls/ (see DECISIONS "M6: Certificates").
    private readonly string? _managedCertFile;
    private readonly string? _managedKeyFile;

    private ServerCertificateSnapshot _current;
    private (string Message, DateTimeOffset AtUtc)? _lastError;
    private string _lastSeenFingerprint;
    private bool _disposed;

    public ServerCertificateProvider(IOptions<TlsOptions> options, IOptions<DevOptions> dev, TimeProvider time, ILogger<ServerCertificateProvider> logger, IOptions<DataOptions>? data = null)
    {
        _options = options.Value;
        _time = time;
        _logger = logger;

        if (data is not null && !string.IsNullOrWhiteSpace(data.Value.Path))
        {
            var folder = Path.Combine(Path.GetFullPath(data.Value.Path), ManagedFolderName);
            _managedCertFile = Path.Combine(folder, ManagedCertFileName);
            _managedKeyFile = Path.Combine(folder, ManagedKeyFileName);
        }

        if (_options.Validate() is { } problem)
        {
            throw new InvalidOperationException(problem);
        }

        if (_options.HasFiles)
        {
            string certificatePem, keyPem;
            try
            {
                (certificatePem, keyPem) = ReadFiles();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                throw new InvalidOperationException($"The server certificate files in Tls:CertFile / Tls:KeyFile cannot be read: {ex.Message}", ex);
            }

            try
            {
                _current = ServerCertificateLoader.Load(certificatePem, keyPem, ServerCertificateSource.File, _time.GetUtcNow());
            }
            catch (ServerCertificateException ex)
            {
                throw new InvalidOperationException($"The server certificate in Tls:CertFile / Tls:KeyFile cannot be used: {ex.Message}", ex);
            }

            _lastSeenFingerprint = _current.ContentFingerprint;
            LogLoaded(_current, "loaded");
        }
        else if (TryLoadManaged() is { } managed)
        {
            // Configured files always win; next come the files the console wrote itself (upload or generated test PKI), then the dev certificate.
            _current = managed;
            _lastSeenFingerprint = _current.ContentFingerprint;
            LogLoaded(_current, "loaded from the data volume (console upload or generated test PKI)");
        }
        else if (dev.Value.Enabled)
        {
            _current = GenerateDevelopmentCertificate();
            _lastSeenFingerprint = _current.ContentFingerprint;
            _logger.LogWarning(
                "DEV MODE: no Tls:CertFile/Tls:KeyFile configured, serving a generated throw-away test certificate for localhost (thumbprint {Thumbprint}). Never use this outside local testing.",
                _current.Thumbprint);
        }
        else
        {
            throw new InvalidOperationException(
                "No server certificate is configured. Set Tls:CertFile and Tls:KeyFile (PEM chain and PEM private key), or start with --dev for a generated throw-away test certificate.");
        }

        if (_options.HasFiles)
        {
            _debounceTimer = new Timer(static state => ((ServerCertificateProvider)state!).SafeReload("file event"), this, Timeout.Infinite, Timeout.Infinite);
            StartWatchers();
            _pollTimer = new Timer(static state => ((ServerCertificateProvider)state!).SafeReload("poll"), this, _options.PollInterval, _options.PollInterval);
        }
    }

    public event Action<ServerCertificateSnapshot>? Changed;

    public ServerCertificateSnapshot Current => Volatile.Read(ref _current);

    public ServerCertificateInfo Info => Current.ToInfo(_time.GetUtcNow(), _options.ExpiryWarningDays);

    public (string Message, DateTimeOffset AtUtc)? LastError
    {
        get
        {
            lock (_gate)
            {
                return _lastError;
            }
        }
    }

    /// <summary>For dev mode only: the PEM of the generated root CA that signed the generated server certificate (to trust it in a client).</summary>
    public string? DevelopmentRootCaPem { get; private set; }

    /// <summary>The folder (below <c>Data:Path</c>) where the console keeps an uploaded or generated certificate when <c>Tls:CertFile</c> is not configured.</summary>
    internal const string ManagedFolderName = "tls";

    internal const string ManagedCertFileName = "server-cert.pem";

    internal const string ManagedKeyFileName = "server-key.pem";

    // A bad or half-written managed file is not fatal (it is not operator configuration): the host falls through to dev mode or the "no certificate" start-up error.
    private ServerCertificateSnapshot? TryLoadManaged()
    {
        if (_managedCertFile is null || _managedKeyFile is null || !File.Exists(_managedCertFile) || !File.Exists(_managedKeyFile))
        {
            return null;
        }

        try
        {
            var snapshot = ServerCertificateLoader.Load(ReadShared(_managedCertFile), ReadShared(_managedKeyFile), ServerCertificateSource.Uploaded, _time.GetUtcNow());
            return snapshot;
        }
        catch (Exception ex) when (ex is ServerCertificateException or IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning("The certificate saved on the data volume by the console cannot be used ({ExceptionType}); ignoring it.", ex.GetType().Name);
            return null;
        }
    }

    public Task<ServerCertificateInfo> ReplaceAsync(string certificatePem, string privateKeyPem, CancellationToken cancellationToken = default, ServerCertificateSource source = ServerCertificateSource.Uploaded)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var now = _time.GetUtcNow();
            ServerCertificateSnapshot candidate;
            try
            {
                candidate = ServerCertificateLoader.Load(certificatePem, privateKeyPem, source, now);
                if (candidate.NotAfterUtc <= now)
                {
                    candidate.Dispose();
                    throw new ServerCertificateException("The certificate has expired");
                }
            }
            catch (ServerCertificateException ex)
            {
                RecordError("upload rejected: " + ex.Message);
                throw;
            }

            if (_options.HasFiles)
            {
                // Key first, then certificate: a watcher that fires in between sees a mismatch and keeps the old certificate.
                WriteAtomically(_options.KeyFile!, privateKeyPem, secret: true);
                WriteAtomically(_options.CertFile!, certificatePem, secret: false);
            }
            else if (_managedCertFile is not null && _managedKeyFile is not null)
            {
                // No configured files: persist next to the other state on the data volume so the certificate survives a restart. The key is written with
                // owner-only permissions where the OS has them, and is never logged, returned or shown.
                Directory.CreateDirectory(Path.GetDirectoryName(_managedKeyFile)!);
                WriteAtomically(_managedKeyFile, privateKeyPem, secret: true);
                WriteAtomically(_managedCertFile, certificatePem, secret: false);
            }

            _lastSeenFingerprint = candidate.ContentFingerprint;
            Swap(candidate);
            _lastError = null;
            return Task.FromResult(Info);
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
        }

        // Stop the event sources first, so nothing can touch a disposed timer.
        foreach (var watcher in _watchers)
        {
            watcher.EnableRaisingEvents = false;
            watcher.Dispose();
        }

        _pollTimer?.Dispose();
        _debounceTimer?.Dispose();
        _current.Dispose();
    }

    // A timer callback must never throw (an unhandled exception on a timer thread ends the process).
    private void SafeReload(string trigger)
    {
        try
        {
            ReloadFromFiles(trigger);
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Server certificate reload ({Trigger}) failed unexpectedly ({ExceptionType}); keeping the current certificate.", trigger, ex.GetType().Name);
        }
    }

    /// <summary>Reloads now if the files changed. Called by the watcher, the poll timer and tests; never throws.</summary>
    internal void ReloadFromFiles(string trigger)
    {
        if (!_options.HasFiles)
        {
            return;
        }

        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            try
            {
                var (certificatePem, keyPem) = ReadFiles();
                var fingerprint = Fingerprint(certificatePem, keyPem);
                if (fingerprint == _lastSeenFingerprint)
                {
                    return;
                }

                // Whatever happens below, this exact content is judged once: an unusable file is not re-parsed (and re-logged) every poll.
                _lastSeenFingerprint = fingerprint;
                var now = _time.GetUtcNow();
                var candidate = ServerCertificateLoader.Load(certificatePem, keyPem, ServerCertificateSource.File, now);
                if (candidate.NotAfterUtc <= now)
                {
                    candidate.Dispose();
                    throw new ServerCertificateException("The new certificate has expired");
                }

                if (candidate.Thumbprint == _current.Thumbprint)
                {
                    candidate.Dispose();
                    _lastError = null;
                    return;
                }

                Swap(candidate);
                _lastError = null;
                _logger.LogInformation("Server certificate reloaded ({Trigger}): thumbprint {Thumbprint}", trigger, candidate.Thumbprint);
            }
            catch (Exception ex) when (ex is ServerCertificateException or IOException or UnauthorizedAccessException)
            {
                RecordError($"reload ({trigger}) failed, keeping the current certificate: {ex.Message}");
            }
        }
    }

    // Caller holds _gate.
    private void Swap(ServerCertificateSnapshot candidate)
    {
        var previous = Interlocked.Exchange(ref _current, candidate);
        LogLoaded(candidate, "now serving");

        // A handshake that started before the swap may still be using the old certificate; release it after a grace period.
        _ = Task.Delay(_options.RetiredCertificateGrace).ContinueWith(_ => previous.Dispose(), CancellationToken.None, TaskContinuationOptions.None, TaskScheduler.Default);

        try
        {
            Changed?.Invoke(candidate);
        }
        catch (Exception ex)
        {
            _logger.LogWarning("A server certificate change subscriber failed: {ExceptionType}", ex.GetType().Name);
        }
    }

    private void RecordError(string message)
    {
        _lastError = (message, _time.GetUtcNow());
        _logger.LogWarning("Server certificate: {Message}", message);
    }

    private void LogLoaded(ServerCertificateSnapshot snapshot, string verb)
    {
        var info = snapshot.ToInfo(_time.GetUtcNow(), _options.ExpiryWarningDays);
        _logger.LogInformation(
            "Server certificate {Verb}: subject={Subject} san={San} not_after={NotAfter:O} chain_length={ChainLength} thumbprint={Thumbprint} source={Source}",
            verb,
            info.Subject,
            string.Join(',', info.SubjectAlternativeNames),
            info.NotAfterUtc,
            info.ChainLength,
            info.ThumbprintSha256,
            info.Source);
        if (info.IsExpired)
        {
            _logger.LogError("The server certificate has EXPIRED ({NotAfter:O}); clients will refuse it.", info.NotAfterUtc);
        }
        else if (info.ExpiresSoon)
        {
            _logger.LogWarning("The server certificate expires within {Days} days ({NotAfter:O}).", _options.ExpiryWarningDays, info.NotAfterUtc);
        }
    }

    private ServerCertificateSnapshot GenerateDevelopmentCertificate()
    {
        using var root = CertificateAuthority.CreateRoot("EkmMock Development Root CA " + Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(4)), PkiKeyAlgorithm.EcdsaP256, TimeSpan.FromDays(90));
        using var server = root.IssueServer(["localhost", "127.0.0.1", "::1"], TimeSpan.FromDays(60));
        DevelopmentRootCaPem = root.CertificatePem;
        return ServerCertificateLoader.Load(server.ChainPem, server.PrivateKeyPem, ServerCertificateSource.DevelopmentGenerated, _time.GetUtcNow());
    }

    private void StartWatchers()
    {
        var directories = new[] { _options.CertFile!, _options.KeyFile! }
            .Select(static f => Path.GetDirectoryName(Path.GetFullPath(f))!)
            .Distinct(StringComparer.OrdinalIgnoreCase);
        var names = new[] { _options.CertFile!, _options.KeyFile! }.Select(static f => Path.GetFileName(f)).ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var directory in directories)
        {
            try
            {
                var watcher = new FileSystemWatcher(directory)
                {
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime,
                    IncludeSubdirectories = false,
                };
                void OnEvent(string? name)
                {
                    if (name is null || !names.Contains(name))
                    {
                        return;
                    }

                    try
                    {
                        _debounceTimer?.Change(_options.Debounce, Timeout.InfiniteTimeSpan);
                    }
                    catch (ObjectDisposedException)
                    {
                        // Shutting down.
                    }
                }

                watcher.Changed += (_, e) => OnEvent(e.Name);
                watcher.Created += (_, e) => OnEvent(e.Name);
                watcher.Deleted += (_, e) => OnEvent(e.Name);
                watcher.Renamed += (_, e) => OnEvent(e.Name);
                watcher.Error += (_, e) => _logger.LogWarning("Server certificate file watcher error ({ExceptionType}); the poll fallback still applies.", e.GetException().GetType().Name);
                watcher.EnableRaisingEvents = true;
                _watchers.Add(watcher);
            }
            catch (Exception ex) when (ex is ArgumentException or IOException or PlatformNotSupportedException)
            {
                _logger.LogWarning("Cannot watch {Directory} for server certificate changes ({ExceptionType}); relying on the poll fallback.", directory, ex.GetType().Name);
            }
        }
    }

    private (string CertificatePem, string KeyPem) ReadFiles() => (ReadShared(_options.CertFile!), ReadShared(_options.KeyFile!));

    private static string ReadShared(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private static string Fingerprint(string certificatePem, string keyPem)
        => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(certificatePem + "\n--\n" + keyPem)));

    private static void WriteAtomically(string path, string content, bool secret)
    {
        var temp = path + ".tmp-" + Guid.NewGuid().ToString("N");
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
        if (secret && !OperatingSystem.IsWindows())
        {
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }

        try
        {
            using (var stream = new FileStream(temp, options))
            using (var writer = new StreamWriter(stream))
            {
                writer.Write(content);
            }

            File.Move(temp, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temp))
            {
                File.Delete(temp);
            }
        }
    }
}
