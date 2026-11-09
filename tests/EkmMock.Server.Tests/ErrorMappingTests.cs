using EkmMock.Crypto;
using EkmMock.Server.Ekm;
using Microsoft.AspNetCore.Http;

namespace EkmMock.Server.Tests;

/// <summary>Spec 4.4: "Map engine exceptions to statuses in one place." The mapping is proven exhaustively here.</summary>
public sealed class ErrorMappingTests
{
    // The documented table (DECISIONS.md "EKM error mapping"). A new EkmErrorKind must be added here deliberately.
    private static readonly Dictionary<EkmErrorKind, (int Status, string Code)> Expected = new()
    {
        [EkmErrorKind.KeyNotFound] = (404, "KeyNotFound"),
        [EkmErrorKind.KeyDisabled] = (403, "KeyDisabled"),
        [EkmErrorKind.KeyExpired] = (403, "KeyExpired"),
        [EkmErrorKind.UnsupportedAlgorithm] = (400, "UnsupportedAlgorithm"),
        [EkmErrorKind.InvalidInput] = (400, "InvalidRequest"),
        [EkmErrorKind.InvalidCiphertext] = (400, "InvalidCiphertext"),
        [EkmErrorKind.HsmUnavailable] = (503, "HsmUnavailable"),
        [EkmErrorKind.InvalidKeyName] = (400, "InvalidKeyName"),
        [EkmErrorKind.KeyAlreadyExists] = (500, "InternalError"),
        [EkmErrorKind.KeyNameReserved] = (500, "InternalError"),
        [EkmErrorKind.OperationNotAllowed] = (403, "OperationNotAllowed"),
        [EkmErrorKind.InternalError] = (500, "InternalError"),
    };

    public static TheoryData<EkmErrorKind> AllKinds()
    {
        var data = new TheoryData<EkmErrorKind>();
        foreach (var kind in Enum.GetValues<EkmErrorKind>())
        {
            data.Add(kind);
        }

        return data;
    }

    [Fact]
    public void TheExpectedTable_CoversEveryEngineErrorKind()
    {
        Expected.Keys.Order().ShouldBe(Enum.GetValues<EkmErrorKind>().Order());
    }

    [Theory]
    [MemberData(nameof(AllKinds))]
    public void EveryEngineErrorKind_MapsToTheDocumentedStatusAndCode(EkmErrorKind kind)
    {
        var mapped = ProxyErrors.Map(new EkmEngineException(kind, "engine detail that must never reach a client"), EkmOperation.WrapKey);

        mapped.StatusCode.ShouldBe(Expected[kind].Status);
        mapped.Code.ToString().ShouldBe(Expected[kind].Code);
        ProxyErrors.StatusOf(ProxyErrors.FromEngine(kind)).ShouldBe(Expected[kind].Status);
        mapped.Message.ShouldNotContain("engine detail");
        mapped.Message.ShouldNotBeNullOrWhiteSpace();
    }

    [Fact]
    public void FromEngine_ForAnUndefinedKind_IsInternalError()
    {
        ProxyErrors.FromEngine((EkmErrorKind)9999).ShouldBe(ProxyErrorCode.InternalError);
    }

    [Fact]
    public void EveryProxyErrorCode_HasAStatusAndAMessage_AndTheDocumentedClasses()
    {
        foreach (var code in Enum.GetValues<ProxyErrorCode>())
        {
            ProxyErrors.StatusOf(code).ShouldBeInRange(400, 599);
            ProxyErrors.DefaultMessage(code, EkmOperation.UnwrapKey).ShouldNotBeNullOrWhiteSpace();
        }

        // Spec 4.4 table.
        ProxyErrors.StatusOf(ProxyErrorCode.InvalidRequest).ShouldBe(400);
        ProxyErrors.StatusOf(ProxyErrorCode.InvalidKeyName).ShouldBe(400);
        ProxyErrors.StatusOf(ProxyErrorCode.UnsupportedApiVersion).ShouldBe(400);
        ProxyErrors.StatusOf(ProxyErrorCode.UnsupportedAlgorithm).ShouldBe(400);
        ProxyErrors.StatusOf(ProxyErrorCode.InvalidCiphertext).ShouldBe(400);
        ProxyErrors.StatusOf(ProxyErrorCode.Unauthenticated).ShouldBe(401);
        ProxyErrors.StatusOf(ProxyErrorCode.KeyDisabled).ShouldBe(403);
        ProxyErrors.StatusOf(ProxyErrorCode.KeyExpired).ShouldBe(403);
        ProxyErrors.StatusOf(ProxyErrorCode.OperationNotAllowed).ShouldBe(403);
        ProxyErrors.StatusOf(ProxyErrorCode.KeyNotFound).ShouldBe(404);
        ProxyErrors.StatusOf(ProxyErrorCode.NotFound).ShouldBe(404);
        ProxyErrors.StatusOf(ProxyErrorCode.MethodNotAllowed).ShouldBe(405);
        ProxyErrors.StatusOf(ProxyErrorCode.TooManyRequests).ShouldBe(429);
        ProxyErrors.StatusOf(ProxyErrorCode.HsmUnavailable).ShouldBe(503);
        ProxyErrors.StatusOf(ProxyErrorCode.InternalError).ShouldBe(500);
    }

    [Fact]
    public void KeyDisabledAndExpired_MessagesNameTheOperation_LikeTheLearnExample()
    {
        ProxyErrors.DefaultMessage(ProxyErrorCode.KeyDisabled, EkmOperation.WrapKey).ShouldBe("Operation WrapKey is not allowed on a disabled key");
        ProxyErrors.DefaultMessage(ProxyErrorCode.KeyExpired, EkmOperation.UnwrapKey).ShouldBe("Operation UnwrapKey is not allowed on an expired key");
    }

    [Fact]
    public void AnUnexpectedException_IsAGenericInternalError_AndOnlyItsTypeIsReported()
    {
        var mapped = ProxyErrors.Map(new InvalidOperationException("SECRET-DETAIL-0123456789 key bytes"), EkmOperation.Metadata);

        mapped.StatusCode.ShouldBe(500);
        mapped.Code.ShouldBe(ProxyErrorCode.InternalError);
        mapped.Message.ShouldBe("An internal error occurred");
        mapped.UnexpectedExceptionType.ShouldBe(nameof(InvalidOperationException));
    }

    [Fact]
    public void TransportRejections_AreInvalidRequest()
    {
        var mapped = ProxyErrors.Map(new BadHttpRequestException("details", 413), null);

        mapped.StatusCode.ShouldBe(400);
        mapped.Code.ShouldBe(ProxyErrorCode.InvalidRequest);
        mapped.Message.ShouldNotContain("details");
    }

    [Fact]
    public void ProtocolExceptions_KeepTheirOwnLiteralMessage()
    {
        var mapped = ProxyErrors.Map(new EkmProtocolException(ProxyErrorCode.InvalidRequest, "The alg field is required"), EkmOperation.WrapKey);

        mapped.Message.ShouldBe("The alg field is required");
        mapped.UnexpectedExceptionType.ShouldBeNull();
    }

    [Fact]
    public void TheEngineKindMapping_ExistsInExactlyOneSourceFile()
    {
        // Spec 4.4: "Map engine exceptions to statuses in one place."
        var serverSources = Directory.EnumerateFiles(RepoPaths.Src("EkmMock.Server"), "*.cs", SearchOption.AllDirectories)
            .Where(static f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}") && !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}"));

        var usingKinds = serverSources
            .Where(static f => File.ReadAllText(f).Contains("EkmErrorKind.", StringComparison.Ordinal))
            .Select(Path.GetFileName)
            .ToList();

        // ProxyErrors.cs is the one mapping of engine failures to the EKM wire contract (status + code). AdminCommon.cs maps the same kinds to the *console* error codes of the
        // management actions (a different contract: /api/console and the pages, never the EKM wire); it is the second and last place.
        usingKinds.ShouldBe(["ProxyErrors.cs", "AdminCommon.cs"], ignoreOrder: true);
    }
}

/// <summary>Finds the repository folders from the test binary location.</summary>
internal static class RepoPaths
{
    public static string Root
    {
        get
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "EkmMock.sln")))
            {
                dir = dir.Parent;
            }

            return dir?.FullName ?? throw new InvalidOperationException("EkmMock.sln not found above the test binaries");
        }
    }

    public static string Src(string project) => Path.Combine(Root, "src", project);
}
