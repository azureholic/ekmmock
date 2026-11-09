using System.Buffers;
using System.Buffers.Text;
using System.Text;
using EkmMock.Server.Ekm;

namespace EkmMock.Server.Tests;

/// <summary>Spec 4.5 and 14 test 12 at codec level, plus the evidence for open question 7.</summary>
public sealed class Base64UrlTests
{
    private static bool TryDecode(string text, out byte[] decoded)
    {
        var utf8 = Encoding.ASCII.GetBytes(text);
        var buffer = new byte[Base64UrlCodec.MaxDecodedLength(utf8.Length) + 4];
        var ok = Base64UrlCodec.TryDecode(utf8, buffer, out var written);
        decoded = ok ? buffer[..written] : [];
        return ok;
    }

    // ---- Open question 7: what does System.Buffers.Text.Base64Url do in the .NET version in use? ---------------------------

    [Theory]
    [InlineData("AQAB", 3)]
    [InlineData("AQ", 1)]
    [InlineData("AQ==", 1)]
    [InlineData("AQA=", 2)]
    [InlineData("AQA", 2)]
    public void OQ7_Runtime_Base64Url_AcceptsPaddedAndUnpaddedInput(string text, int expectedLength)
    {
        Base64Url.IsValid(text).ShouldBeTrue();
        Base64Url.DecodeFromChars(text).Length.ShouldBe(expectedLength);

        var dest = new byte[16];
        Base64Url.DecodeFromUtf8(Encoding.ASCII.GetBytes(text), dest, out _, out var written, isFinalBlock: true).ShouldBe(OperationStatus.Done);
        written.ShouldBe(expectedLength);
    }

    [Theory]
    [InlineData("+/+/")]
    [InlineData("AQ/B")]
    [InlineData("A+AB")]
    [InlineData("A")]
    [InlineData("AQ=B")]
    [InlineData("AQ===")]
    [InlineData("AQAB=")]
    public void OQ7_Runtime_Base64Url_RejectsStandardAlphabetAndMalformedPadding(string text)
    {
        Base64Url.IsValid(text).ShouldBeFalse();
    }

    [Theory]
    [InlineData("AQ A")]
    [InlineData("AQ\n")]
    public void OQ7_Runtime_Base64Url_SkipsWhitespace_SoTheCodecMustRejectItItself(string text)
    {
        // Pins the runtime behaviour that makes the strict pre-scan in Base64UrlCodec necessary.
        Base64Url.IsValid(text).ShouldBeTrue();
        TryDecode(text, out _).ShouldBeFalse();
    }

    // ---- Base64UrlCodec ------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("", 0)]
    [InlineData("AQAB", 3)]
    [InlineData("AQ", 1)]
    [InlineData("AQ==", 1)]
    [InlineData("AQA", 2)]
    [InlineData("AQA=", 2)]
    [InlineData("-_-_", 3)]
    [InlineData("MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2Nzg", 32)] // the Learn example value (unpadded)
    public void Decode_AcceptsPaddedAndUnpadded(string text, int expectedLength)
    {
        TryDecode(text, out var decoded).ShouldBeTrue();
        decoded.Length.ShouldBe(expectedLength);
    }

    [Theory]
    [InlineData("+/+/")]
    [InlineData("AQ+B")]
    [InlineData("AQ/B")]
    [InlineData("AQ A")]
    [InlineData(" AQAB")]
    [InlineData("AQAB ")]
    [InlineData("AQ\tAB")]
    [InlineData("AQ\nAB")]
    [InlineData("AQ\rAB")]
    [InlineData("A")]
    [InlineData("AQAAA")]
    [InlineData("=")]
    [InlineData("==")]
    [InlineData("=AQA")]
    [InlineData("AQ=")]
    [InlineData("AQ===")]
    [InlineData("AQ=B")]
    [InlineData("AQAB=")]
    [InlineData("AQ==AQ==")]
    [InlineData("AB==")] // non-canonical trailing bits
    [InlineData("AQ*B")]
    [InlineData("AQ.B")]
    public void Decode_RejectsEverythingElse(string text)
    {
        TryDecode(text, out _).ShouldBeFalse();
    }

    [Fact]
    public void Decode_RejectsNonAsciiBytes()
    {
        var buffer = new byte[16];
        Base64UrlCodec.TryDecode([0xC3, 0xA9, 0x41, 0x41], buffer, out _).ShouldBeFalse();
    }

    [Fact]
    public void Encode_NeverPads_AndRoundTripsEveryLengthUpTo300()
    {
        for (var length = 0; length <= 300; length++)
        {
            var raw = Fx.Random(length);
            var encoded = new byte[Base64UrlCodec.EncodedLength(length)];
            Base64UrlCodec.Encode(raw, encoded).ShouldBe(encoded.Length);
            Encoding.ASCII.GetString(encoded).ShouldNotContain("=");
            Encoding.ASCII.GetString(encoded).ShouldNotContain("+");
            Encoding.ASCII.GetString(encoded).ShouldNotContain("/");

            TryDecode(Encoding.ASCII.GetString(encoded), out var back).ShouldBeTrue();
            Fx.Same(back, raw).ShouldBeTrue();
        }
    }

    [Fact]
    public void Encode_Exponent65537_IsAQAB()
    {
        var encoded = new byte[4];
        Base64UrlCodec.Encode([0x01, 0x00, 0x01], encoded);
        Encoding.ASCII.GetString(encoded).ShouldBe("AQAB");
    }
}
