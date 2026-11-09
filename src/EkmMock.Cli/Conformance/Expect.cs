using EkmMock.Cli.Ekm;

namespace EkmMock.Cli.Conformance;

/// <summary>Assertions for the conformance checks. Messages never contain a response body that could hold a DEK: a successful answer is described by its size only.</summary>
internal static class Expect
{
    public static void That(bool condition, string message)
    {
        if (!condition)
        {
            throw new TestFailure(message);
        }
    }

    public static void Status(EkmReply reply, int expected, string what)
        => That(reply.Status == expected, $"{what}: expected HTTP {expected}, got {Describe(reply)}");

    /// <summary>Expects a ProxyError (spec 4.4): the status, a JSON body and the <c>code</c>.</summary>
    public static void ProxyError(EkmReply reply, int status, string code, string what)
    {
        That(reply.Status == status, $"{what}: expected HTTP {status} {code}, got {Describe(reply)}");
        That(reply.ContentType?.StartsWith("application/json", StringComparison.OrdinalIgnoreCase) == true, $"{what}: the error body is not application/json (Content-Type '{reply.ContentType}')");
        That(reply.ErrorCode == code, $"{what}: expected error code {code}, got '{reply.ErrorCode}'");
        That(reply.GetString("message") is { Length: > 0 }, $"{what}: the error body has no message");
    }

    /// <summary>Any ProxyError with the given status (for checks where the spec fixes the status but not the code).</summary>
    public static void AnyProxyError(EkmReply reply, int status, string what)
    {
        That(reply.Status == status, $"{what}: expected HTTP {status}, got {Describe(reply)}");
        That(reply.ErrorCode is { Length: > 0 }, $"{what}: the answer is not a ProxyError body with a code");
    }

    /// <summary>A short description of an answer that is safe to print.</summary>
    public static string Describe(EkmReply reply)
        => reply.Status is >= 200 and < 300
            ? $"{reply.Status} (body of {reply.Body.Length} bytes)"
            : $"{reply.Status} {Truncate(reply.Text, 200)}";

    public static string Truncate(string text, int max) => text.Length <= max ? text : text[..max] + "...";

    /// <summary>The <c>value</c> of a successful wrap/unwrap answer, decoded; fails when it is missing, padded or not base64url.</summary>
    public static byte[] Value(EkmReply reply, string what, bool allowPadding = false)
    {
        Status(reply, 200, what);
        var text = reply.GetString("value");
        That(text is { Length: > 0 }, $"{what}: the answer has no 'value'");
        That(allowPadding || !text!.Contains('=', StringComparison.Ordinal), $"{what}: the value is padded; the spec requires unpadded base64url output");
        That(!text!.Contains('+', StringComparison.Ordinal) && !text.Contains('/', StringComparison.Ordinal), $"{what}: the value uses '+' or '/', so it is not base64url");
        try
        {
            return EkmClient.FromBase64Url(text);
        }
        catch (FormatException)
        {
            throw new TestFailure($"{what}: the value is not valid base64url");
        }
    }
}
