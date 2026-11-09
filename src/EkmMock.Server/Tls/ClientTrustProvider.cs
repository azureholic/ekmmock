using System.Security.Cryptography.X509Certificates;
using EkmMock.Crypto;

namespace EkmMock.Server.Tls;

/// <summary>One namespace's client trust, parsed: its own root CAs and its exact (case-sensitive) common-name allow-list.</summary>
internal sealed class NamespaceTrust
{
    public NamespaceTrust(X509Certificate2Collection roots, IReadOnlySet<string> commonNames)
    {
        Roots = roots;
        CommonNames = commonNames;
    }

    public X509Certificate2Collection Roots { get; }

    /// <summary>Compared with <see cref="StringComparer.Ordinal"/>: no case folding, no wildcards, no substrings.</summary>
    public IReadOnlySet<string> CommonNames { get; }
}

/// <summary>
/// An immutable view of all namespaces' trust at one moment: the union of every root CA (used at handshake time, when the
/// namespace is not known yet) and the per-namespace sets (used by authorization once the path has resolved the namespace).
/// </summary>
internal sealed class ClientTrustSnapshot : IDisposable
{
    private readonly List<X509Certificate2> _owned;

    public ClientTrustSnapshot(IReadOnlyList<NamespaceDefinition> source)
    {
        Source = source;
        _owned = [];
        UnionRoots = [];
        var byNamespace = new Dictionary<string, NamespaceTrust>(StringComparer.Ordinal);
        var unionThumbprints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var definition in source)
        {
            var roots = new X509Certificate2Collection();
            foreach (var base64 in definition.ClientTrust.CaCertificatesDerBase64)
            {
                // The store validated these when the namespace was saved; a bad entry is skipped rather than failing everyone.
                X509Certificate2 certificate;
                try
                {
                    certificate = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(base64));
                }
                catch (Exception ex) when (ex is FormatException or System.Security.Cryptography.CryptographicException)
                {
                    continue;
                }

                _owned.Add(certificate);
                roots.Add(certificate);
                if (unionThumbprints.Add(certificate.Thumbprint))
                {
                    UnionRoots.Add(certificate);
                }
            }

            byNamespace[definition.Name] = new NamespaceTrust(roots, new HashSet<string>(definition.ClientTrust.SubjectCommonNames, StringComparer.Ordinal));
        }

        ByNamespace = byNamespace;
    }

    /// <summary>The namespace list instance this snapshot was built from (the store publishes a new list on every change).</summary>
    public IReadOnlyList<NamespaceDefinition> Source { get; }

    /// <summary>Every namespace's roots once; the custom trust store of the handshake validation.</summary>
    public X509Certificate2Collection UnionRoots { get; }

    public IReadOnlyDictionary<string, NamespaceTrust> ByNamespace { get; }

    public void Dispose()
    {
        foreach (var certificate in _owned)
        {
            certificate.Dispose();
        }
    }
}

/// <summary>
/// Hands out the current <see cref="ClientTrustSnapshot"/>. The namespace store publishes an immutable list on every change,
/// so a changed reference means changed trust: the next caller rebuilds the snapshot and swaps it in atomically
/// (compare-and-swap; two racing callers may both build, one wins, the loser is disposed). No restart, no timer, no stale window.
/// Retired snapshots are disposed after a grace period, because a validation that started before the swap may still use them.
/// </summary>
internal sealed class ClientTrustProvider : IDisposable
{
    private static readonly TimeSpan RetireGrace = TimeSpan.FromSeconds(30);

    private readonly NamespaceStore _namespaces;
    private ClientTrustSnapshot _current;
    private bool _disposed;

    public ClientTrustProvider(NamespaceStore namespaces)
    {
        _namespaces = namespaces;
        _current = new ClientTrustSnapshot(namespaces.List());
    }

    public ClientTrustSnapshot Current
    {
        get
        {
            var source = _namespaces.List();
            var snapshot = Volatile.Read(ref _current);
            if (ReferenceEquals(snapshot.Source, source))
            {
                return snapshot;
            }

            return Refresh(snapshot, source);
        }
    }

    private ClientTrustSnapshot Refresh(ClientTrustSnapshot observed, IReadOnlyList<NamespaceDefinition> source)
    {
        var candidate = new ClientTrustSnapshot(source);
        var previous = Interlocked.CompareExchange(ref _current, candidate, observed);
        if (ReferenceEquals(previous, observed))
        {
            Retire(observed);
            return candidate;
        }

        // Somebody else swapped first; use theirs (it may already be newer than ours) and drop ours.
        candidate.Dispose();
        return Volatile.Read(ref _current);
    }

    private static void Retire(ClientTrustSnapshot snapshot)
        => _ = Task.Delay(RetireGrace).ContinueWith(_ => snapshot.Dispose(), CancellationToken.None, TaskContinuationOptions.None, TaskScheduler.Default);

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _current.Dispose();
    }
}
