using System.Buffers.Binary;

namespace EkmMock.Server.Connections;

internal enum ClientHelloParseStatus
{
    /// <summary>Not enough bytes yet (or the connection ended before the hello was complete).</summary>
    NeedMoreData,

    Parsed,

    /// <summary>The first bytes are not a TLS handshake record.</summary>
    NotTls,

    /// <summary>It started like TLS but is not a ClientHello we can read (fragmented across records, corrupt, ...).</summary>
    Malformed,
}

/// <summary>What a client said it supports. Read passively from the first bytes of the connection, before any TLS stack touches them.</summary>
internal sealed record ClientHelloInfo(
    ushort LegacyVersion,
    IReadOnlyList<ushort> SupportedVersions,
    IReadOnlyList<ushort> CipherSuites,
    string? ServerName,
    IReadOnlyList<string> Alpn)
{
    public const ushort Tls13 = 0x0304;

    /// <summary>The versions the client offered: the <c>supported_versions</c> extension, or the legacy version of a TLS 1.2-and-older client.</summary>
    public IReadOnlyList<ushort> OfferedVersions => SupportedVersions.Count > 0 ? SupportedVersions : [LegacyVersion];

    public bool OffersTls13 => OfferedVersions.Contains(Tls13);

    public bool OffersAnyOf(ushort first, ushort second) => CipherSuites.Contains(first) || CipherSuites.Contains(second);

    public static string VersionName(ushort version) => version switch
    {
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ when IsGrease(version) => "GREASE",
        _ => $"0x{version:X4}",
    };

    public static string? Tls13SuiteName(ushort suite) => suite switch
    {
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0x1304 => "TLS_AES_128_CCM_SHA256",
        0x1305 => "TLS_AES_128_CCM_8_SHA256",
        _ => null,
    };

    // RFC 8701: 0x?A?A values are random "GREASE" placeholders.
    internal static bool IsGrease(ushort value) => (value & 0x0F0F) == 0x0A0A && (value >> 8) == (value & 0xFF);
}

/// <summary>
/// Parses the ClientHello at the start of a TLS connection (RFC 8446 section 4.1.2, RFC 5246 section 7.4.1.2). It exists because
/// the TLS stacks (SChannel, OpenSSL) report handshake failures with OS-specific, unstable messages, whereas "what the client offered"
/// is identical everywhere: that is what lets EkmMock say <em>TLS 1.2 only client</em> or <em>no permitted cipher suite</em> reliably.
/// Pure and allocation-light; reads at most the first TLS record.
/// </summary>
internal static class ClientHelloParser
{
    /// <summary>Largest TLS record payload (2^14) plus the 5 byte record header.</summary>
    public const int MaxRecordBytes = 16384 + 5;

    private const byte HandshakeRecord = 0x16;
    private const byte ClientHelloType = 0x01;
    private const ushort ExtServerName = 0x0000;
    private const ushort ExtAlpn = 0x0010;
    private const ushort ExtSupportedVersions = 0x002B;

    public static ClientHelloParseStatus TryParse(ReadOnlySpan<byte> data, out ClientHelloInfo? info)
    {
        info = null;
        if (data.Length >= 1 && data[0] != HandshakeRecord)
        {
            return ClientHelloParseStatus.NotTls;
        }

        if (data.Length >= 2 && data[1] != 0x03)
        {
            return ClientHelloParseStatus.NotTls;
        }

        if (data.Length < 5)
        {
            return ClientHelloParseStatus.NeedMoreData;
        }

        var recordLength = BinaryPrimitives.ReadUInt16BigEndian(data[3..5]);
        if (recordLength < 4 || recordLength > 16384)
        {
            return ClientHelloParseStatus.Malformed;
        }

        if (data.Length < 5 + recordLength)
        {
            return ClientHelloParseStatus.NeedMoreData;
        }

        var record = data.Slice(5, recordLength);
        if (record[0] != ClientHelloType)
        {
            return ClientHelloParseStatus.Malformed;
        }

        var handshakeLength = (record[1] << 16) | (record[2] << 8) | record[3];
        if (handshakeLength > record.Length - 4)
        {
            // The hello continues in another record (very large hellos). Not worth reassembling here.
            return ClientHelloParseStatus.Malformed;
        }

        var reader = new Reader(record.Slice(4, handshakeLength));
        if (!reader.TryReadUInt16(out var legacyVersion) || !reader.TrySkip(32) || !reader.TrySkipVector8())
        {
            return ClientHelloParseStatus.Malformed;
        }

        if (!reader.TryReadVector16(out var suiteBytes) || (suiteBytes.Length & 1) != 0)
        {
            return ClientHelloParseStatus.Malformed;
        }

        var suites = new List<ushort>(suiteBytes.Length / 2);
        for (var i = 0; i < suiteBytes.Length; i += 2)
        {
            var suite = BinaryPrimitives.ReadUInt16BigEndian(suiteBytes.Slice(i, 2));
            if (!ClientHelloInfo.IsGrease(suite))
            {
                suites.Add(suite);
            }
        }

        if (!reader.TrySkipVector8())
        {
            return ClientHelloParseStatus.Malformed;
        }

        var versions = new List<ushort>();
        var alpn = new List<string>();
        string? serverName = null;

        // Extensions are optional (a bare TLS 1.0 hello has none).
        if (reader.Remaining > 0)
        {
            if (!reader.TryReadVector16(out var extensions))
            {
                return ClientHelloParseStatus.Malformed;
            }

            var ext = new Reader(extensions);
            while (ext.Remaining > 0)
            {
                if (!ext.TryReadUInt16(out var type) || !ext.TryReadVector16(out var body))
                {
                    return ClientHelloParseStatus.Malformed;
                }

                switch (type)
                {
                    case ExtSupportedVersions:
                        ReadSupportedVersions(body, versions);
                        break;
                    case ExtServerName:
                        serverName = ReadServerName(body);
                        break;
                    case ExtAlpn:
                        ReadAlpn(body, alpn);
                        break;
                }
            }
        }

        info = new ClientHelloInfo(legacyVersion, versions, suites, serverName, alpn);
        return ClientHelloParseStatus.Parsed;
    }

    private static void ReadSupportedVersions(ReadOnlySpan<byte> body, List<ushort> versions)
    {
        if (body.Length < 1 || body[0] != body.Length - 1)
        {
            return;
        }

        for (var i = 1; i + 1 < body.Length; i += 2)
        {
            var version = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(i, 2));
            if (!ClientHelloInfo.IsGrease(version))
            {
                versions.Add(version);
            }
        }
    }

    private static string? ReadServerName(ReadOnlySpan<byte> body)
    {
        var reader = new Reader(body);
        if (!reader.TryReadVector16(out var list))
        {
            return null;
        }

        var names = new Reader(list);
        while (names.Remaining > 0)
        {
            if (!names.TryReadUInt8(out var nameType) || !names.TryReadVector16(out var name))
            {
                return null;
            }

            if (nameType == 0)
            {
                return SafeHostName(name);
            }
        }

        return null;
    }

    private static void ReadAlpn(ReadOnlySpan<byte> body, List<string> protocols)
    {
        var reader = new Reader(body);
        if (!reader.TryReadVector16(out var list))
        {
            return;
        }

        var items = new Reader(list);
        while (items.Remaining > 0 && protocols.Count < 8)
        {
            if (!items.TryReadVector8(out var protocol))
            {
                return;
            }

            if (SafeHostName(protocol, allowSlash: true) is { } text)
            {
                protocols.Add(text);
            }
        }
    }

    // The SNI and ALPN values are client controlled and end up in events and logs: keep only hostname-like ASCII, bounded.
    private static string? SafeHostName(ReadOnlySpan<byte> bytes, bool allowSlash = false)
    {
        if (bytes.Length == 0 || bytes.Length > 255)
        {
            return null;
        }

        Span<char> chars = stackalloc char[bytes.Length];
        for (var i = 0; i < bytes.Length; i++)
        {
            var b = bytes[i];
            var ok = b is (>= (byte)'a' and <= (byte)'z') or (>= (byte)'A' and <= (byte)'Z') or (>= (byte)'0' and <= (byte)'9') or (byte)'.' or (byte)'-' or (byte)'_'
                || (allowSlash && b == (byte)'/');
            if (!ok)
            {
                return null;
            }

            chars[i] = (char)b;
        }

        return new string(chars);
    }

    private ref struct Reader
    {
        private ReadOnlySpan<byte> _data;

        public Reader(ReadOnlySpan<byte> data) => _data = data;

        public readonly int Remaining => _data.Length;

        public bool TrySkip(int count)
        {
            if (_data.Length < count)
            {
                return false;
            }

            _data = _data[count..];
            return true;
        }

        public bool TryReadUInt8(out byte value)
        {
            value = 0;
            if (_data.Length < 1)
            {
                return false;
            }

            value = _data[0];
            _data = _data[1..];
            return true;
        }

        public bool TryReadUInt16(out ushort value)
        {
            value = 0;
            if (_data.Length < 2)
            {
                return false;
            }

            value = BinaryPrimitives.ReadUInt16BigEndian(_data);
            _data = _data[2..];
            return true;
        }

        public bool TryReadVector8(out ReadOnlySpan<byte> vector)
        {
            vector = default;
            if (_data.Length < 1 || _data.Length < 1 + _data[0])
            {
                return false;
            }

            vector = _data.Slice(1, _data[0]);
            _data = _data[(1 + vector.Length)..];
            return true;
        }

        public bool TrySkipVector8() => TryReadVector8(out _);

        public bool TryReadVector16(out ReadOnlySpan<byte> vector)
        {
            vector = default;
            if (_data.Length < 2)
            {
                return false;
            }

            var length = BinaryPrimitives.ReadUInt16BigEndian(_data);
            if (_data.Length < 2 + length)
            {
                return false;
            }

            vector = _data.Slice(2, length);
            _data = _data[(2 + length)..];
            return true;
        }
    }
}
