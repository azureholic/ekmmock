using System.Text.Json.Serialization.Metadata;

namespace EkmMock.Server.Ekm;

/// <summary>Writes EKM responses. Every body this endpoint sends is <c>application/json</c> (spec 4.1).</summary>
internal static class EkmResponse
{
    private const string JsonContentType = "application/json";

    private static ReadOnlySpan<byte> ValuePrefix => "{\"value\":\""u8;

    private static ReadOnlySpan<byte> ValueSuffix => "\"}"u8;

    public static Task WriteJsonAsync<T>(HttpContext context, int statusCode, T value, JsonTypeInfo<T> typeInfo, CancellationToken cancellationToken = default)
    {
        var bytes = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(value, typeInfo);
        return WriteBytesAsync(context, statusCode, bytes, cancellationToken);
    }

    public static Task WriteErrorAsync(HttpContext context, MappedError error)
    {
        if (error.Code == ProxyErrorCode.MethodNotAllowed)
        {
            context.Response.Headers.Allow = "POST";
        }

        return WriteJsonAsync(
            context,
            error.StatusCode,
            new ProxyError(error.Code.ToString(), error.Message),
            EkmJsonContext.Default.ProxyError);
    }

    /// <summary>
    /// Builds <c>{"value":"&lt;base64url&gt;"}</c> straight into a caller-owned buffer, so the (possibly secret)
    /// bytes never exist as a <see cref="string"/>. Returns the number of bytes written.
    /// </summary>
    public static int BuildValueBody(ReadOnlySpan<byte> raw, byte[] destination)
    {
        ValuePrefix.CopyTo(destination);
        var written = Base64UrlCodec.Encode(raw, destination.AsSpan(ValuePrefix.Length));
        ValueSuffix.CopyTo(destination.AsSpan(ValuePrefix.Length + written));
        return ValuePrefix.Length + written + ValueSuffix.Length;
    }

    public static int ValueBodyLength(int rawLength) => ValuePrefix.Length + Base64UrlCodec.EncodedLength(rawLength) + ValueSuffix.Length;

    public static Task WriteBytesAsync(HttpContext context, int statusCode, ReadOnlyMemory<byte> body, CancellationToken cancellationToken = default)
    {
        var response = context.Response;
        response.StatusCode = statusCode;
        response.ContentType = JsonContentType;
        response.ContentLength = body.Length;
        return response.Body.WriteAsync(body, cancellationToken).AsTask();
    }
}
