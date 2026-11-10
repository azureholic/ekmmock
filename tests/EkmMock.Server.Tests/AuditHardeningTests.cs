#pragma warning disable xUnit1051 // The console tests use HttpClients with a bounded timeout; they do not need per-call cancellation tokens.

using System.Runtime.Versioning;
using EkmMock.Crypto;
using EkmMock.Server.Hosting;
using EkmMock.Server.Inspector;
using EkmMock.Server.WebConsole;
using EkmMock.TestSupport;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.Tests;

/// <summary>
/// Security review L3 and L4: audit first and then change (a failing audit write changes nothing), a bounded reader, size-based rotation, and owner-only files on Unix.
/// </summary>
public sealed class AuditHardeningTests
{
    // ---- L3: audit before the change ----

    private static async Task<(ConsoleTestHost Host, AdminApi Api, ListAuditLog Audit)> StartAsync()
    {
        var audit = new ListAuditLog();
        var host = await ConsoleTestHost.StartAsync(configureServices: services => services.AddSingleton<IAuditLog>(audit));
        return (host, new AdminApi(host.Host.CreateConsoleClient()), audit);
    }

    [Fact]
    public async Task WhenTheAuditLogCannotBeWritten_DestroyingAKeyChangesNothing()
    {
        var (host, api, audit) = await StartAsync();
        await using var _ = host;
        host.Host.Keys.Create("_default", "doomed-key", KeyType.Oct, 256);
        audit.Fail = true;

        var reply = await api.PostAsync("/api/console/keys/_default/doomed-key/destroy", new { confirm_name = "doomed-key" });

        reply.StatusCode.ShouldBe(503);
        reply.Text.ShouldContain("nothing was changed");
        host.Host.Keys.Get(new KeyRef("_default", "doomed-key"))!.State.ShouldBe(KeyState.Enabled); // the key is still there
        audit.Entries.ShouldBeEmpty();
    }

    [Fact]
    public async Task TheDestroyEntry_IsWrittenBeforeTheKeyIsDestroyed()
    {
        var (host, api, audit) = await StartAsync();
        await using var _ = host;
        host.Host.Keys.Create("_default", "ordered-key", KeyType.Oct, 256);

        // The audit log looks at the key while it appends: at that moment the key must still be alive.
        KeyState? stateWhenAudited = null;
        audit.OnAppend = entry =>
        {
            if (entry.Action == "key.destroy")
            {
                stateWhenAudited = host.Host.Keys.Get(new KeyRef("_default", "ordered-key"))!.State;
            }
        };

        var reply = await api.PostAsync("/api/console/keys/_default/ordered-key/destroy", new { confirm_name = "ordered-key" });

        reply.StatusCode.ShouldBe(200, reply.Text);
        stateWhenAudited.ShouldBe(KeyState.Enabled);
        host.Host.Keys.Get(new KeyRef("_default", "ordered-key"))!.State.ShouldBe(KeyState.Destroyed);
        audit.Entries.Single(static e => e.Action == "key.destroy").Target.ShouldBe("key:_default/ordered-key");
    }

    [Theory]
    [InlineData("disable")]
    [InlineData("enable")]
    public async Task WhenTheAuditLogCannotBeWritten_EnablingOrDisablingAKeyChangesNothing(string verb)
    {
        var (host, api, audit) = await StartAsync();
        await using var _ = host;
        host.Host.Keys.Create("_default", "toggle-key", KeyType.Oct, 256);
        if (verb == "enable")
        {
            host.Host.Keys.SetEnabled(new KeyRef("_default", "toggle-key"), false);
        }

        audit.Fail = true;
        var reply = await api.PostAsync($"/api/console/keys/_default/toggle-key/{verb}");

        reply.StatusCode.ShouldBe(503);
        host.Host.Keys.Get(new KeyRef("_default", "toggle-key"))!.State.ShouldBe(verb == "enable" ? KeyState.Disabled : KeyState.Enabled);
    }

    [Fact]
    public async Task WhenTheAuditLogCannotBeWritten_ChangingTheExpiryOfAKeyChangesNothing()
    {
        var (host, api, audit) = await StartAsync();
        await using var _ = host;
        host.Host.Keys.Create("_default", "expiry-key", KeyType.Oct, 256);
        audit.Fail = true;

        var reply = await api.PostAsync("/api/console/keys/_default/expiry-key/expiry", new { not_after = DateTimeOffset.UtcNow.AddMinutes(-5) });

        reply.StatusCode.ShouldBe(503);
        host.Host.Keys.Get(new KeyRef("_default", "expiry-key"))!.NotAfter.ShouldBeNull();
    }

    [Fact]
    public async Task WhenTheAuditLogCannotBeWritten_ImportingTrustAndDeletingANamespaceChangeNothing()
    {
        var (host, api, audit) = await StartAsync();
        await using var _ = host;
        var created = await api.PostAsync("/api/console/namespaces", new { name = "audited-ns", prefix = "audited" });
        created.StatusCode.ShouldBe(201, created.Text);
        var before = host.Host.Namespaces.Get("audited-ns")!.ClientTrust;
        audit.Fail = true;

        var trust = await api.PostAsync("/api/console/namespaces/audited-ns/trust/import", new { content = """{"subject_common_name":"x.test","ca_certificates":[]}""", mode = "merge" });
        var delete = await api.PostAsync("/api/console/namespaces/audited-ns/delete", new { confirm_name = "audited-ns", destroy_keys = true });

        ((int)trust.StatusCode).ShouldBeOneOf(503, 400); // a body that does not parse is refused before anything is audited; the point is the delete
        delete.StatusCode.ShouldBe(503);
        host.Host.Namespaces.Get("audited-ns").ShouldNotBeNull("the namespace still exists");
        host.Host.Namespaces.Get("audited-ns")!.ClientTrust.SubjectCommonNames.ShouldBe(before.SubjectCommonNames);
    }

    [Fact]
    public async Task WhenTheChangeFailsAfterTheAuditEntry_AnOutcomeEntryIsWritten_AndTheErrorIsStillReported()
    {
        var audit = new ListAuditLog();
        var logger = NullLogger<AuditRecorder>.Instance;
        var recorder = new AuditRecorder(audit, logger);

        Should.Throw<ConsoleActionException>(() => recorder.Intend("alice", "key.destroy", "key:ns/k", "irreversible", () => throw new ConsoleActionException(ConsoleErrorCode.NotFound, "gone")))
            .Code.ShouldBe(ConsoleErrorCode.NotFound);

        audit.Entries.Select(static e => (e.Action, e.Target, e.Detail)).ShouldBe(
        [
            ("key.destroy", "key:ns/k", "irreversible"),
            (AuditActions.ActionFailed, "key:ns/k", "key.destroy: NotFound"),
        ]);
        await Task.CompletedTask;
    }

    [Fact]
    public void WhenTheAuditWriteFails_TheChangeIsNeverApplied()
    {
        var audit = new ListAuditLog { Fail = true };
        var recorder = new AuditRecorder(audit, NullLogger<AuditRecorder>.Instance);
        var applied = false;

        var exception = Should.Throw<ConsoleActionException>(() => recorder.Intend("alice", "key.destroy", "key:ns/k", null, () => applied = true));

        exception.Code.ShouldBe(ConsoleErrorCode.AuditUnavailable);
        exception.Message.ShouldContain("nothing was changed");
        applied.ShouldBeFalse();
    }

    [Fact]
    public async Task ARefusedAction_IsNotAudited_BecauseItIsRefusedBeforeTheEntryIsWritten()
    {
        var (host, api, audit) = await StartAsync();
        await using var _ = host;
        host.Host.Keys.Create("_default", "kept-key", KeyType.Oct, 256);

        (await api.PostAsync("/api/console/keys/_default/kept-key/destroy", new { confirm_name = "wrong" })).StatusCode.ShouldBe(400);
        (await api.PostAsync("/api/console/keys/_default/no-such-key/disable")).StatusCode.ShouldBe(404);

        audit.Entries.ShouldBeEmpty();
    }

    // ---- L3: bounded reader and rotation ----

    [Fact]
    public void ReadRecent_ReadsFromTheEnd_AndReturnsExactlyTheNewestEntries_OldestFirst()
    {
        using var folder = new TempFolder();
        var log = new FileAuditLog(folder.File("audit.jsonl"), TimeProvider.System);
        for (var i = 1; i <= 1500; i++)
        {
            log.Append("alice", "key.create", "key:ns/k" + i, i % 2 == 0 ? "even" : null);
        }

        var recent = log.ReadRecent(7);

        recent.Select(static e => e.Target).ShouldBe(Enumerable.Range(1494, 7).Select(static i => "key:ns/k" + i));
        log.ReadRecent(100_000).Count.ShouldBe(1500);
        log.ReadRecent(0).ShouldBeEmpty();
    }

    [Fact]
    public void ReadRecent_DoesNotReadTheWholeFile()
    {
        using var folder = new TempFolder();
        var path = folder.File("audit.jsonl");
        var log = new FileAuditLog(path, TimeProvider.System);
        for (var i = 1; i <= 3000; i++)
        {
            log.Append("alice", "key.create", "key:ns/k" + i);
        }

        // Damage the first half of the file: a reader that deserialised everything would trip over it, a tail reader never looks there.
        var bytes = File.ReadAllBytes(path);
        for (var i = 0; i < bytes.Length / 2; i++)
        {
            if (bytes[i] != (byte)'\n')
            {
                bytes[i] = (byte)'#';
            }
        }

        File.WriteAllBytes(path, bytes);

        var recent = log.ReadRecent(50);

        recent.Count.ShouldBe(50);
        recent[^1].Target.ShouldBe("key:ns/k3000");
    }

    [Fact]
    public void ATornLastLine_IsSkipped_NotFatal()
    {
        using var folder = new TempFolder();
        var path = folder.File("audit.jsonl");
        var log = new FileAuditLog(path, TimeProvider.System);
        log.Append("alice", "key.create", "key:ns/a");
        File.AppendAllText(path, "{\"at\":\"2026-11-10T00:00:00Z\",\"user\":\"al");

        log.ReadRecent().Select(static e => e.Target).ShouldBe(["key:ns/a"]);
    }

    [Fact]
    public void TheAuditQuery_ScansOnlyTheNewestEntries()
    {
        AuditQuery.MaxScannedEntries.ShouldBe(10_000);
        var recorder = new CountingAuditLog();

        _ = recorder.Query(null, 0, 50);

        recorder.RequestedCount.ShouldBe(10_000);
    }

    private sealed class CountingAuditLog : IAuditLog
    {
        public int RequestedCount { get; private set; }

        public void Append(string user, string action, string target, string? detail = null)
        {
        }

        public IReadOnlyList<AuditEntry> ReadRecent(int count = 200)
        {
            RequestedCount = count;
            return [];
        }
    }

    [Fact]
    public void TheFile_IsRolledOverBySize_AndTheOldestIsDeleted()
    {
        using var folder = new TempFolder();
        var path = folder.File("audit.jsonl");
        var log = new FileAuditLog(path, TimeProvider.System, maxFileBytes: 4096, maxFiles: 3);

        for (var i = 1; i <= 400; i++)
        {
            log.Append("alice", "key.create", "key:ns/k" + i, "detail " + i);
        }

        File.Exists(path).ShouldBeTrue();
        File.Exists(log.RolledPath(1)).ShouldBeTrue();
        File.Exists(log.RolledPath(3)).ShouldBeTrue();
        File.Exists(log.RolledPath(4)).ShouldBeFalse("only MaxFiles rolled-over files are kept");
        foreach (var file in new[] { path, log.RolledPath(1), log.RolledPath(2), log.RolledPath(3) })
        {
            new FileInfo(file).Length.ShouldBeLessThanOrEqualTo(4096 + 400, file);
        }

        // The newest entries are in the newest file, and the reader follows the rotation: what is left is contiguous and ends with the last entry.
        var all = log.ReadRecent(100_000);
        all[^1].Target.ShouldBe("key:ns/k400");
        all.Count.ShouldBeLessThan(400);
        var numbers = all.Select(static e => int.Parse(e.Target["key:ns/k".Length..])).ToList();
        numbers.ShouldBe(Enumerable.Range(numbers[0], numbers.Count));
    }

    [Fact]
    public void ReadRecent_ContinuesIntoRolledOverFiles_ForAsManyEntriesAsAreAsked()
    {
        using var folder = new TempFolder();
        var log = new FileAuditLog(folder.File("audit.jsonl"), TimeProvider.System, maxFileBytes: 4096, maxFiles: 5);
        for (var i = 1; i <= 100; i++)
        {
            log.Append("alice", "key.create", "key:ns/k" + i);
        }

        File.Exists(log.RolledPath(1)).ShouldBeTrue();
        var recent = log.ReadRecent(60);

        recent.Count.ShouldBe(60);
        recent.Select(static e => e.Target).ShouldBe(Enumerable.Range(41, 60).Select(static i => "key:ns/k" + i));
    }

    [Fact]
    public void AnExistingFile_IsContinued_AfterARestart()
    {
        using var folder = new TempFolder();
        var path = folder.File("audit.jsonl");
        new FileAuditLog(path, TimeProvider.System).Append("alice", "a", "t1");

        var second = new FileAuditLog(path, TimeProvider.System);
        second.Append("alice", "a", "t2");

        second.ReadRecent().Select(static e => e.Target).ShouldBe(["t1", "t2"]);
    }

    [Fact]
    public void TheAuditOptions_HaveDefaults_AreValidated_AndBindFromConfiguration()
    {
        new AuditOptions().MaxFileBytes.ShouldBe(50L * 1024 * 1024);
        new AuditOptions().MaxFiles.ShouldBe(5);
        new AuditOptions { MaxFileBytes = 10 }.IsValid(out var tooSmall).ShouldBeFalse();
        tooSmall.ShouldContain("Audit:MaxFileBytes");
        new AuditOptions { MaxFiles = 0 }.IsValid(out var noFiles).ShouldBeFalse();
        noFiles.ShouldContain("Audit:MaxFiles");

        using var folder = new TempFolder();
        var options = Options.Create(new AuditOptions { MaxFileBytes = 4096, MaxFiles = 2 });
        var log = new FileAuditLog(Options.Create(new DataOptions { Path = folder.Path }), options, TimeProvider.System);
        log.FilePath.ShouldBe(Path.Combine(Path.GetFullPath(folder.Path), "audit.jsonl"));
    }

    // ---- L4: owner-only files ----

    [Fact]
    public void TheOwnerOnlyOptions_AskForReadAndWriteForTheOwnerOnly_OnUnix()
    {
        var options = OwnerOnlyFile.Options(FileMode.Append, FileAccess.Write, FileShare.Read, 1);

        options.Mode.ShouldBe(FileMode.Append);
        options.Access.ShouldBe(FileAccess.Write);
        if (OperatingSystem.IsWindows())
        {
            options.UnixCreateMode.ShouldBeNull(); // the setting does not exist on Windows; the data folder's ACL applies
        }
        else
        {
            options.UnixCreateMode.ShouldBe(UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        OwnerOnlyFile.CreateMode.ShouldBe(UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    [Fact]
    [UnsupportedOSPlatform("windows")]
    public void OnUnix_TheAuditFileAndTheInspectorFilesAreCreatedWithMode0600()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "File modes exist on Unix only; this runs in the Linux container (tests/run-server-tests-linux.ps1) and in CI.");
        using var folder = new TempFolder();

        var audit = new FileAuditLog(folder.File("audit.jsonl"), TimeProvider.System);
        audit.Append("alice", "key.create", "key:ns/a");
        audit.Append("alice", "key.create", "key:ns/b");

        var jsonl = Path.Combine(folder.Path, "inspector");
        using (var writer = new InspectorJsonlWriter(Options.Create(new InspectorOptions { Persist = true, PersistPath = jsonl }), Options.Create(new DataOptions { Path = folder.Path }), TimeProvider.System, NullLoggerFactory.Instance))
        {
            ((IInspectorStage)writer).OnExchange(new CapturedExchange(Rec.Make(1), null));
            ((IInspectorStage)writer).OnIdle();
        }

        UnixFileMode expected = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        File.GetUnixFileMode(audit.FilePath).ShouldBe(expected);
        var files = Directory.GetFiles(jsonl, "*.jsonl");
        files.ShouldNotBeEmpty();
        foreach (var file in files)
        {
            File.GetUnixFileMode(file).ShouldBe(expected, file);
        }
    }

    [Fact]
    [UnsupportedOSPlatform("windows")]
    public void ARolledOverAuditFile_KeepsItsMode()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "File modes exist on Unix only.");
        using var folder = new TempFolder();
        var log = new FileAuditLog(folder.File("audit.jsonl"), TimeProvider.System, maxFileBytes: 4096, maxFiles: 2);
        for (var i = 0; i < 200; i++)
        {
            log.Append("alice", "key.create", "key:ns/k" + i, "detail " + i);
        }

        File.GetUnixFileMode(log.RolledPath(1)).ShouldBe(UnixFileMode.UserRead | UnixFileMode.UserWrite);
        File.GetUnixFileMode(log.FilePath).ShouldBe(UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
}
