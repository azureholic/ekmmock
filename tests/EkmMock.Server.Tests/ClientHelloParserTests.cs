using System.Buffers.Binary;
using System.IO.Pipelines;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using EkmMock.Server.Connections;

namespace EkmMock.Server.Tests;

/// <summary>
/// The ClientHello reader and the transport tap behind the handshake-failure reasons. The hellos come from a real <see cref="SslStream"/>
/// client (so they are exactly what SChannel/OpenSSL send), plus hand-built and corrupted ones.
/// </summary>
public sealed class ClientHelloParserTests
{
    /// <summary>Connects a real SslStream client to a bare TCP listener and returns the first bytes it sends (the ClientHello).</summary>
    internal static async Task<byte[]> CaptureHelloAsync(SslClientAuthenticationOptions options)
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var clientTask = Task.Run(async () =>
        {
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(IPAddress.Loopback, port);
            using var ssl = new SslStream(tcp.GetStream());
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                await ssl.AuthenticateAsClientAsync(options, cts.Token);
            }
            catch (Exception)
            {
                // Expected: the "server" never answers.
            }
        });

        using var server = await listener.AcceptTcpClientAsync(TestContext.Current.CancellationToken);
        var stream = server.GetStream();
        var buffer = new byte[ClientHelloParser.MaxRecordBytes];
        var length = 0;
        while (length < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(length), TestContext.Current.CancellationToken);
            if (read == 0)
            {
                break;
            }

            length += read;
            if (ClientHelloParser.TryParse(buffer.AsSpan(0, length), out _) != ClientHelloParseStatus.NeedMoreData)
            {
                break;
            }
        }

        server.Close();
        await clientTask;
        return buffer[..length];
    }

    private static SslClientAuthenticationOptions Options(SslProtocols protocols, string host = "ekm.example.test")
        => new() { TargetHost = host, EnabledSslProtocols = protocols, RemoteCertificateValidationCallback = static (_, _, _, _) => true };

    [Fact]
    public async Task ARealTls13Client_OffersTls13_Sni_Alpn_AndTheAesSuites()
    {
        var options = Options(SslProtocols.Tls13);
        options.ApplicationProtocols = [SslApplicationProtocol.Http2, SslApplicationProtocol.Http11];
        var hello = await CaptureHelloAsync(options);

        ClientHelloParser.TryParse(hello, out var info).ShouldBe(ClientHelloParseStatus.Parsed);

        info.ShouldNotBeNull();
        info.OffersTls13.ShouldBeTrue();
        info.OfferedVersions.ShouldBe([ClientHelloInfo.Tls13]);
        info.ServerName.ShouldBe("ekm.example.test");
        info.Alpn.ShouldBe(["h2", "http/1.1"]);
        info.OffersAnyOf(0x1301, 0x1302).ShouldBeTrue();
    }

    [Fact]
    public async Task ARealTls12OnlyClient_DoesNotOfferTls13()
    {
        var hello = await CaptureHelloAsync(Options(SslProtocols.Tls12));

        ClientHelloParser.TryParse(hello, out var info).ShouldBe(ClientHelloParseStatus.Parsed);

        info.ShouldNotBeNull();
        info.OffersTls13.ShouldBeFalse();
        info.OfferedVersions.Select(ClientHelloInfo.VersionName).ShouldBe(["TLS 1.2"]);
    }

    [Fact]
    public async Task AClientOfferingTls12AndTls13_OffersBoth()
    {
        var hello = await CaptureHelloAsync(Options(SslProtocols.Tls12 | SslProtocols.Tls13));

        ClientHelloParser.TryParse(hello, out var info).ShouldBe(ClientHelloParseStatus.Parsed);

        info.ShouldNotBeNull().OffersTls13.ShouldBeTrue();
        info.OfferedVersions.ShouldContain((ushort)0x0303);
    }

    [Fact]
    public async Task AnIpAddressTarget_SendsNoServerName()
    {
        var hello = await CaptureHelloAsync(Options(SslProtocols.Tls13, host: "127.0.0.1"));

        ClientHelloParser.TryParse(hello, out var info).ShouldBe(ClientHelloParseStatus.Parsed);

        info.ShouldNotBeNull().ServerName.ShouldBeNull();
    }

    [Fact]
    public async Task EveryProperPrefixOfAHello_NeedsMoreData_AndNeverThrows()
    {
        var hello = await CaptureHelloAsync(Options(SslProtocols.Tls13));

        for (var length = 0; length < hello.Length; length++)
        {
            ClientHelloParser.TryParse(hello.AsSpan(0, length), out var info).ShouldBe(ClientHelloParseStatus.NeedMoreData, $"prefix {length}");
            info.ShouldBeNull();
        }

        ClientHelloParser.TryParse(hello, out _).ShouldBe(ClientHelloParseStatus.Parsed);
    }

    [Fact]
    public async Task CorruptedHellos_NeverThrow_AndNeverClaimToBeBetterThanTheyAre()
    {
        var hello = await CaptureHelloAsync(Options(SslProtocols.Tls13));
        var random = new Random(1234);

        for (var i = 0; i < 2000; i++)
        {
            var mutated = (byte[])hello.Clone();
            for (var flips = random.Next(1, 4); flips > 0; flips--)
            {
                mutated[random.Next(mutated.Length)] = (byte)random.Next(256);
            }

            var status = ClientHelloParser.TryParse(mutated.AsSpan(0, random.Next(mutated.Length + 1)), out var info);
            Enum.IsDefined(status).ShouldBeTrue();
            (status == ClientHelloParseStatus.Parsed).ShouldBe(info is not null);
        }
    }

    [Theory]
    [InlineData("GET / HTTP/1.1\r\nHost: x\r\n\r\n")]
    [InlineData("POST /info?api-version=0.1-preview HTTP/1.1\r\n")]
    [InlineData("\u0080\u0001")]
    public void ClearTextAndNonTlsBytes_AreNotTls(string text)
    {
        var bytes = System.Text.Encoding.Latin1.GetBytes(text);

        ClientHelloParser.TryParse(bytes, out var info).ShouldBe(ClientHelloParseStatus.NotTls);
        info.ShouldBeNull();
    }

    [Fact]
    public void ATlsRecordThatIsNotAClientHello_IsMalformed()
    {
        // Handshake record (0x16, TLS 1.2) carrying a ServerHello (type 2).
        byte[] record = [0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00];

        ClientHelloParser.TryParse(record, out _).ShouldBe(ClientHelloParseStatus.Malformed);
    }

    [Fact]
    public void ATls10StyleHelloWithoutExtensions_ReportsItsLegacyVersionAsTheOnlyOfferedOne()
    {
        var hello = BuildHello(legacyVersion: 0x0301, suites: [0x002F, 0x0035], extensions: null);

        ClientHelloParser.TryParse(hello, out var info).ShouldBe(ClientHelloParseStatus.Parsed);

        info.ShouldNotBeNull();
        info.OfferedVersions.ShouldBe([(ushort)0x0301]);
        info.OffersTls13.ShouldBeFalse();
        ClientHelloInfo.VersionName(0x0301).ShouldBe("TLS 1.0");
    }

    [Fact]
    public void GreaseValues_AreIgnored_AndHostileNamesAreDropped()
    {
        // supported_versions: GREASE 0x1A1A and TLS 1.3; server_name with a control character; ALPN with a path-like name.
        var versions = new byte[] { 0x04, 0x1A, 0x1A, 0x03, 0x04 };
        var evilName = new byte[] { 0x00, 0x08, 0x00, 0x00, 0x05, (byte)'a', (byte)'\r', (byte)'\n', (byte)'b', (byte)'c' };
        var extensions = Concat(Extension(0x002B, versions), Extension(0x0000, evilName));
        var hello = BuildHello(0x0303, [0x1A1A, 0x1302], extensions);

        ClientHelloParser.TryParse(hello, out var info).ShouldBe(ClientHelloParseStatus.Parsed);

        info.ShouldNotBeNull();
        info.OfferedVersions.ShouldBe([ClientHelloInfo.Tls13]);
        info.CipherSuites.ShouldBe([(ushort)0x1302]);
        info.ServerName.ShouldBeNull();
    }

    // ---- the tap: transparent, one report, correct under any chunking and partial consumption -------------------------------------------

    private sealed class DuplexPipe(PipeReader input, PipeWriter output) : IDuplexPipe
    {
        public PipeReader Input { get; } = input;

        public PipeWriter Output { get; } = output;
    }

    private static async Task<(byte[] Received, List<(ClientHelloParseStatus Status, ClientHelloInfo? Info)> Reports)> PumpThroughTapAsync(byte[] data, int chunkSize, bool completeWriter = true)
    {
        var upstream = new Pipe();
        var downstream = new Pipe();
        var reports = new List<(ClientHelloParseStatus, ClientHelloInfo?)>();
        var tap = new ClientHelloTap(new DuplexPipe(upstream.Reader, downstream.Writer), (status, info) => reports.Add((status, info)));

        var writer = Task.Run(async () =>
        {
            for (var offset = 0; offset < data.Length; offset += chunkSize)
            {
                var length = Math.Min(chunkSize, data.Length - offset);
                await upstream.Writer.WriteAsync(data.AsMemory(offset, length));
            }

            if (completeWriter)
            {
                await upstream.Writer.CompleteAsync();
            }
        });

        var received = new List<byte>();
        var random = new Random(7);
        while (received.Count < data.Length)
        {
            var result = await tap.Input.ReadAsync(TestContext.Current.CancellationToken);
            var buffer = result.Buffer;

            // Consume only part of what is available (and examine all of it), the way SslStream reads a record header first.
            var take = (int)Math.Max(1, Math.Min(buffer.Length, random.Next(1, 40)));
            foreach (var segment in buffer.Slice(0, take))
            {
                received.AddRange(segment.ToArray());
            }

            tap.Input.AdvanceTo(buffer.GetPosition(take), buffer.End);
            if (result.IsCompleted && buffer.Length == take)
            {
                break;
            }
        }

        await writer;
        await tap.Input.CompleteAsync();
        return ([.. received], reports);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(100)]
    [InlineData(100000)]
    public async Task TheTap_PassesEveryByteThroughUnchanged_AndReportsTheHelloExactlyOnce(int chunkSize)
    {
        var hello = await CaptureHelloAsync(Options(SslProtocols.Tls13));
        var payload = hello.Concat(Enumerable.Range(0, 3000).Select(static i => (byte)(i * 31))).ToArray();

        var (received, reports) = await PumpThroughTapAsync(payload, chunkSize);

        received.ShouldBe(payload);
        reports.Count.ShouldBe(1);
        reports[0].Status.ShouldBe(ClientHelloParseStatus.Parsed);
        reports[0].Info.ShouldNotBeNull().OffersTls13.ShouldBeTrue();
    }

    [Fact]
    public async Task TheTap_ReportsNotTls_ForPlainHttp_AndStillPassesTheBytes()
    {
        var payload = System.Text.Encoding.ASCII.GetBytes("GET /info HTTP/1.1\r\nHost: x\r\n\r\n");

        var (received, reports) = await PumpThroughTapAsync(payload, chunkSize: 5);

        received.ShouldBe(payload);
        reports.ShouldBe([(ClientHelloParseStatus.NotTls, null)]);
    }

    [Fact]
    public async Task TheTap_ReportsAnIncompleteHello_WhenThePeerClosesEarly()
    {
        var hello = await CaptureHelloAsync(Options(SslProtocols.Tls13));
        var partial = hello[..40];

        var (received, reports) = await PumpThroughTapAsync(partial, chunkSize: 10);

        received.ShouldBe(partial);
        reports.Count.ShouldBe(1);
        reports[0].Status.ShouldBe(ClientHelloParseStatus.NeedMoreData);
    }

    // ---- hello builder ------------------------------------------------------------------------------------------------------------------

    private static byte[] Concat(params byte[][] parts) => [.. parts.SelectMany(static p => p)];

    private static byte[] Extension(ushort type, byte[] body)
    {
        var bytes = new byte[4 + body.Length];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, type);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(2), (ushort)body.Length);
        body.CopyTo(bytes, 4);
        return bytes;
    }

    private static byte[] BuildHello(ushort legacyVersion, ushort[] suites, byte[]? extensions)
    {
        var body = new List<byte>();
        body.AddRange([(byte)(legacyVersion >> 8), (byte)legacyVersion]);
        body.AddRange(new byte[32]);
        body.Add(0); // empty session id
        body.AddRange([(byte)((suites.Length * 2) >> 8), (byte)(suites.Length * 2)]);
        foreach (var suite in suites)
        {
            body.AddRange([(byte)(suite >> 8), (byte)suite]);
        }

        body.AddRange([1, 0]); // compression: null
        if (extensions is not null)
        {
            body.AddRange([(byte)(extensions.Length >> 8), (byte)extensions.Length]);
            body.AddRange(extensions);
        }

        var handshake = new List<byte> { 0x01, (byte)(body.Count >> 16), (byte)(body.Count >> 8), (byte)body.Count };
        handshake.AddRange(body);
        var record = new List<byte> { 0x16, 0x03, 0x01, (byte)(handshake.Count >> 8), (byte)handshake.Count };
        record.AddRange(handshake);
        return [.. record];
    }
}
