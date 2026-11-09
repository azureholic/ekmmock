using System.Buffers.Text;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using EkmMock.Crypto;
using EkmMock.Server.Connections;
using EkmMock.Server.Ekm;
using EkmMock.Server.Hosting;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.Tests;

internal sealed class TempDir : IDisposable
{
    public TempDir()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "ekmmock-server-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path, recursive: true);
        }
        catch (IOException)
        {
            // Best-effort cleanup of a temp folder.
        }
    }
}

/// <summary>Everything a test factory can vary. Defaults are a fresh data folder and a fixed synthetic master key.</summary>
internal sealed class EkmFactoryOptions
{
    /// <summary>Reuse an existing data folder (restart tests). Null creates and owns a temp folder.</summary>
    public string? DataPath { get; init; }

    public string MasterKeyLabel { get; init; } = "default";

    public bool AllowKeyImport { get; init; }

    public bool SeedSampleKeys { get; init; }

    public bool StrictSelfTest { get; init; }

    public IEngineAvailability? Availability { get; init; }

    public IMasterKeyProvider? MasterKeyProvider { get; init; }

    public Dictionary<string, string?> Configuration { get; init; } = [];

    public Action<IServiceCollection>? ConfigureServices { get; init; }

    public bool CaptureLogs { get; init; } = true;
}

/// <summary>The EKM server in the in-process test host: plain HTTP, no Kestrel, no TLS (M2).</summary>
internal sealed class EkmFactory : WebApplicationFactory<Program>
{
    private readonly TempDir? _ownedData;
    private readonly EkmFactoryOptions _options;

    public EkmFactory(EkmFactoryOptions? options = null)
    {
        _options = options ?? new EkmFactoryOptions();
        if (_options.DataPath is null)
        {
            _ownedData = new TempDir();
        }

        DataPath = _options.DataPath ?? _ownedData!.Path;
        Logs = new CapturingLoggerProvider();
    }

    public string DataPath { get; }

    public CapturingLoggerProvider Logs { get; }

    public static byte[] MasterKeyBytes(string label = "default")
        => SHA256.HashData(Encoding.UTF8.GetBytes("ekmmock-server-test-master:" + label));

    public SoftwareCryptoBackend Backend => Services.GetRequiredService<SoftwareCryptoBackend>();

    public IKeyManager Keys => Services.GetRequiredService<IKeyManager>();

    public NamespaceStore Namespaces => Services.GetRequiredService<NamespaceStore>();

    public EkmClient CreateEkmClient() => new(CreateClient());

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(_options.Configuration));

        builder.ConfigureLogging(logging =>
        {
            logging.ClearProviders();
            if (_options.CaptureLogs)
            {
                logging.AddProvider(Logs);
            }

            logging.SetMinimumLevel(LogLevel.Information);
        });

        builder.ConfigureTestServices(services =>
        {
            // PostConfigure is applied after every configuration source, so a test can never touch a real data folder.
            services.PostConfigure<DataOptions>(o => o.Path = DataPath);
            services.PostConfigure<DevOptions>(o => o.SeedSampleKeys = _options.SeedSampleKeys);
            services.PostConfigure<SelfTestSettings>(o => o.Strict = _options.StrictSelfTest);

            var provider = _options.MasterKeyProvider ?? new ExplicitMasterKeyProvider(MasterKeyBytes(_options.MasterKeyLabel));
            services.AddSingleton(provider);
            services.AddSingleton(sp => new SoftwareCryptoBackendOptions
            {
                DataPath = DataPath,
                MasterKeyProvider = provider,
                AllowKeyImport = _options.AllowKeyImport,
                CounterFlushInterval = TimeSpan.Zero,
                Info = new BackendInfo("EkmMock", "EkmMock Software HSM"),
            });

            if (_options.Availability is { } availability)
            {
                services.AddSingleton(availability);
            }

            // The in-process test host has no TLS and no client certificates, so the M2 handler tests replace the two transport-level
            // seams here, in the test host's own DI. Production has no such switch (see ArchitectureTests): the real listener always
            // runs the mTLS authorizer, and EKM routes answer only on the EKM listener ports.
            services.AddSingleton<IEkmCallerAuthorizer, AllowAllCallerAuthorizer>();
            services.AddSingleton<IEkmPortPolicy, AnyPortPolicy>();

            _options.ConfigureServices?.Invoke(services);
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
        {
            _ownedData?.Dispose();
        }
    }
}

internal sealed class FixedAvailability : IEngineAvailability
{
    public FixedAvailability(bool available) => IsAvailable = available;

    public bool IsAvailable { get; set; }
}

/// <summary>Test host only: the in-process server has no client certificates, so every caller is "authorized" there.</summary>
internal sealed class AllowAllCallerAuthorizer : IEkmCallerAuthorizer
{
    public EkmAuthResult Authorize(HttpContext context, NamespaceDefinition ns) => EkmAuthResult.Allowed();
}

/// <summary>Test host only: the in-process server has no listener ports, so every request counts as an EKM request.</summary>
internal sealed class AnyPortPolicy : IEkmPortPolicy
{
    public bool IsEkmPort(int localPort) => true;
}

/// <summary>One captured log record: the formatted message, the structured state and any exception, all as text for leak scans.</summary>
internal sealed record CapturedLog(string Category, LogLevel Level, string Message, IReadOnlyDictionary<string, object?> Fields, string? Exception)
{
    public string AllText
        => Message + "\n" + string.Join("\n", Fields.Select(static f => $"{f.Key}={f.Value}")) + "\n" + Exception;
}

internal sealed class CapturingLoggerProvider : ILoggerProvider
{
    private readonly List<CapturedLog> _entries = [];
    private readonly object _gate = new();

    public IReadOnlyList<CapturedLog> Entries
    {
        get
        {
            lock (_gate)
            {
                return [.. _entries];
            }
        }
    }

    public string AllText => string.Join("\n---\n", Entries.Select(static e => e.AllText));

    public ILogger CreateLogger(string categoryName) => new CapturingLogger(this, categoryName);

    public void Dispose()
    {
    }

    private sealed class CapturingLogger : ILogger
    {
        private readonly CapturingLoggerProvider _owner;
        private readonly string _category;

        public CapturingLogger(CapturingLoggerProvider owner, string category)
        {
            _owner = owner;
            _category = category;
        }

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            var fields = new Dictionary<string, object?>();
            if (state is IEnumerable<KeyValuePair<string, object?>> pairs)
            {
                foreach (var pair in pairs)
                {
                    fields[pair.Key] = pair.Value;
                }
            }

            var entry = new CapturedLog(_category, logLevel, formatter(state, exception), fields, exception?.ToString());
            lock (_owner._gate)
            {
                _owner._entries.Add(entry);
            }
        }
    }
}

/// <summary>A parsed EKM reply: status, content type and body. Bodies are only kept as text when they are not secret-bearing.</summary>
internal sealed class EkmReply
{
    public EkmReply(HttpStatusCode status, string? contentType, byte[] body, HttpResponseMessage message)
    {
        Status = status;
        ContentType = contentType;
        Body = body;
        Message = message;
    }

    public HttpStatusCode Status { get; }

    public int StatusCode => (int)Status;

    public string? ContentType { get; }

    public byte[] Body { get; }

    public HttpResponseMessage Message { get; }

    public string Text => Encoding.UTF8.GetString(Body);

    public JsonDocument Json() => JsonDocument.Parse(Body);

    /// <summary>The ProxyError <c>code</c>, or null if the body is not a ProxyError.</summary>
    public string? ErrorCode
    {
        get
        {
            using var doc = Json();
            return doc.RootElement.ValueKind == JsonValueKind.Object && doc.RootElement.TryGetProperty("code", out var c) ? c.GetString() : null;
        }
    }

    /// <summary>The raw bytes of the base64url <c>value</c> field (decoded), for wrap and unwrap replies.</summary>
    public byte[] Value()
    {
        using var doc = Json();
        return Base64Url.DecodeFromChars(doc.RootElement.GetProperty("value").GetString()!);
    }

    public string ValueText()
    {
        using var doc = Json();
        return doc.RootElement.GetProperty("value").GetString()!;
    }

    /// <summary>Asserts the body is exactly a ProxyError: JSON object with only <c>code</c> and <c>message</c>, application/json.</summary>
    public void ShouldBeProxyError(int expectedStatus, string expectedCode)
    {
        StatusCode.ShouldBe(expectedStatus, Text);
        ContentType.ShouldNotBeNull().ShouldStartWith("application/json");
        using var doc = Json();
        doc.RootElement.ValueKind.ShouldBe(JsonValueKind.Object);
        doc.RootElement.EnumerateObject().Select(static p => p.Name).Order().ShouldBe(["code", "message"]);
        doc.RootElement.GetProperty("code").GetString().ShouldBe(expectedCode);
        doc.RootElement.GetProperty("message").GetString().ShouldNotBeNullOrWhiteSpace();
    }
}

/// <summary>Thin helper over the test <see cref="HttpClient"/> that builds EKM requests.</summary>
internal sealed class EkmClient
{
    public const string ApiVersion = "0.1-preview";
    public const string Context = """{"request_context":{"request_id":"6476b291-7c15-4d0b-aef9-03688390cb8e","correlation_id":"aa9a3cb4-82b4-11f0-afc6-5ffd3bdade85","pool_name":"mhsm-pool-name"}}""";

    private readonly HttpClient _http;

    public EkmClient(HttpClient http) => _http = http;

    /// <summary>The HTTP version to request (<see cref="HttpVersionPolicy.RequestVersionOrLower"/>); null keeps the default of 1.1.</summary>
    public Version? RequestVersion { get; init; }

    public HttpClient Http => _http;

    public static string Path(string? prefix, string? key, string op, string? query = "api-version=0.1-preview")
    {
        var p = string.IsNullOrEmpty(prefix) ? string.Empty : "/" + prefix.Trim('/');
        var k = key is null ? string.Empty : "/" + key;
        return $"{p}{k}/{op}" + (query is null ? string.Empty : "?" + query);
    }

    public static StringContent JsonBody(string json, string contentType = "application/json")
    {
        var content = new StringContent(json, Encoding.UTF8);
        content.Headers.ContentType = MediaTypeHeaderValue.Parse(contentType);
        return content;
    }

    public static string WrapBody(string alg, string valueText)
        => $$"""{"request_context":{"request_id":"r","correlation_id":"c","pool_name":"p"},"alg":"{{alg}}","value":"{{valueText}}"}""";

    public async Task<EkmReply> SendAsync(HttpMethod method, string path, HttpContent? content = null)
    {
        var message = new HttpRequestMessage(method, path) { Content = content };
        if (RequestVersion is not null)
        {
            message.Version = RequestVersion;
            message.VersionPolicy = HttpVersionPolicy.RequestVersionOrLower;
        }
        var response = await _http.SendAsync(message);
        var body = await response.Content.ReadAsByteArrayAsync();
        return new EkmReply(response.StatusCode, response.Content.Headers.ContentType?.ToString(), body, response);
    }

    public Task<EkmReply> PostAsync(string path, string? json = null, string contentType = "application/json")
        => SendAsync(HttpMethod.Post, path, JsonBody(json ?? Context, contentType));

    public Task<EkmReply> InfoAsync(string? prefix = null) => PostAsync(Path(prefix, null, "info"));

    public Task<EkmReply> MetadataAsync(string key, string? prefix = null) => PostAsync(Path(prefix, key, "metadata"));

    public Task<EkmReply> WrapAsync(string key, string alg, byte[] dek, string? prefix = null)
        => PostAsync(Path(prefix, key, "wrapkey"), WrapBody(alg, Base64Url.EncodeToString(dek)));

    public Task<EkmReply> UnwrapAsync(string key, string alg, byte[] wrapped, string? prefix = null)
        => PostAsync(Path(prefix, key, "unwrapkey"), WrapBody(alg, Base64Url.EncodeToString(wrapped)));

    public Task<EkmReply> WrapRawAsync(string key, string alg, string valueText, string? prefix = null)
        => PostAsync(Path(prefix, key, "wrapkey"), WrapBody(alg, valueText));

    public Task<EkmReply> UnwrapRawAsync(string key, string alg, string valueText, string? prefix = null)
        => PostAsync(Path(prefix, key, "unwrapkey"), WrapBody(alg, valueText));
}

internal static class Fx
{
    public static byte[] Random(int length) => RandomNumberGenerator.GetBytes(length);

    /// <summary>Secret-safe equality: no byte values end up in assertion output.</summary>
    public static bool Same(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);

    public static string KeyName(string prefix = "k") => $"{prefix}-{Guid.NewGuid():N}"[..Math.Min(40, prefix.Length + 13)];
}

/// <summary>Looks for secret bytes in text as hex and base64/base64url at all alignments (same idea as the M1 scanner).</summary>
internal static class SecretScanner
{
    public static bool LeaksInText(string text, byte[] secret)
    {
        const int probeLength = 24;
        var probes = secret.Length <= probeLength
            ? [secret]
            : new[] { secret[..probeLength], secret[^probeLength..] };
        foreach (var probe in probes)
        {
            if (text.Contains(Convert.ToHexString(probe), StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            for (var alignment = 0; alignment < 3; alignment++)
            {
                if (probe.Length - alignment < 6)
                {
                    continue;
                }

                var b64 = Convert.ToBase64String(probe[alignment..]);
                b64 = b64[..^4];
                if (b64.Length < 8)
                {
                    continue;
                }

                if (text.Contains(b64, StringComparison.Ordinal) || text.Contains(b64.Replace('+', '-').Replace('/', '_'), StringComparison.Ordinal))
                {
                    return true;
                }
            }
        }

        return false;
    }
}
