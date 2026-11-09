using System.Text.Json;
using System.Text.Json.Serialization;
using EkmMock.Server.Inspector;
using Microsoft.AspNetCore.Components;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.WebConsole.Components;

/// <summary>Indented, masked JSON of an exchange for the detail view's copy button. Built from <see cref="ExchangeRecord"/> only, so it can never hold a raw secret.</summary>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    UseStringEnumConverter = true,
    WriteIndented = true)]
[JsonSerializable(typeof(ExchangeRecord))]
internal sealed partial class DetailJsonContext : JsonSerializerContext
{
}

/// <summary>
/// The Exchange detail (spec 8.5.2): Overview, TLS &amp; client certificate, Request, Response and Timing tabs, copy buttons, the ready-made KQL snippet, a Replay button
/// that is enabled only when replay is possible (it sends the same request through the real EKM endpoint with the console test client certificate, audited) and per-field Reveal when reveal is allowed (audited, shown for a short time, never
/// put in a URL, storage or export). Used as the side panel of Live traffic and as the <c>/exchange/{id}</c> page.
/// </summary>
public sealed partial class ExchangeDetailView : IDisposable
{
    /// <summary>How long a revealed value stays on screen.</summary>
    internal const int RevealSeconds = 30;

    private const double AxisPixels = 460;

    private static readonly TabDefinition[] Tabs =
    [
        new("overview", "Overview"),
        new("tls", "TLS & client certificate"),
        new("request", "Request"),
        new("response", "Response"),
        new("timing", "Timing"),
    ];

    private readonly List<WaterfallSegment> _segments = [];
    private ExchangeRecord? _record;
    private KqlSnippet? _kql;
    private ReplayCheck _replay;
    private string _tab = "overview";
    private string? _replayMessage;
    private long? _replayExchangeId;
    private bool _replayBusy;
    private string? _json;
    private long _loadedId = -1;
    private RevealedField? _revealed;
    private string? _revealError;
    private ITimer? _hideTimer;
    private double _budgetMs = 250;
    private double _budgetPx;
    private bool _disposed;

    /// <summary>The exchange to show (its id in the inspector's ring buffer).</summary>
    [Parameter, EditorRequired]
    public long ExchangeId { get; set; }

    /// <summary>Side panel mode: tighter layout.</summary>
    [Parameter]
    public bool Compact { get; set; }

    [Inject]
    private IInspector Inspector { get; set; } = default!;

    [Inject]
    private IConsoleUser CurrentUser { get; set; } = default!;

    [Inject]
    private IConsoleStatusProvider Status { get; set; } = default!;

    [Inject]
    private IOptions<LimitsOptions> Limits { get; set; } = default!;

    [Inject]
    private TimeProvider Time { get; set; } = default!;

    private bool RevealAllowed => Status.Get().RevealAllowed;

    private string ReplayTitle => _replay.Possible
        ? "Send this request again through the EKM endpoint with the console's test client certificate (audited)."
        : _replay.Reason switch
        {
            ReplayBlockReason.RevealNotAllowed => "Replay needs the raw request body, which is kept only when reveal is allowed (EKMMOCK_INSPECTOR_ALLOW_REVEAL=true and Inspector:SecretDisplay=Reveal).",
            ReplayBlockReason.BodyNotRetained => "The raw request body of this exchange was not kept (it was larger than 16 KiB).",
            _ => "The exchange is no longer in the inspector.",
        };

    protected override void OnParametersSet()
    {
        if (ExchangeId == _loadedId)
        {
            return;
        }

        _loadedId = ExchangeId;
        HideRevealed();
        _replayMessage = null;
        _tab = "overview";
        _record = Inspector.Get(ExchangeId);
        _kql = _record is null ? null : Inspector.Kql(ExchangeId);
        _replay = _record is null ? new ReplayCheck(false, ReplayBlockReason.ExchangeNotFound) : Inspector.CanReplay(ExchangeId);
        _json = _record is null ? null : JsonSerializer.Serialize(_record, DetailJsonContext.Default.ExchangeRecord);
        BuildWaterfall();
    }

    private string ExchangeJson(ExchangeRecord record) => _json ?? JsonSerializer.Serialize(record, DetailJsonContext.Default.ExchangeRecord);

    // Replay (M6): the same request is sent again through the real EKM endpoint with the console test client certificate (IInspector.ReplayAsync audits it as
    // inspector.replay). The new exchange is then looked up (it is captured asynchronously) so that the user can follow it into Live traffic.
    private async Task ReplayAsync()
    {
        if (_record is null || _replayBusy)
        {
            return;
        }

        _replayBusy = true;
        _replayMessage = null;
        _replayExchangeId = null;
        try
        {
            var user = await CurrentUser.GetAsync();
            var outcome = await Inspector.ReplayAsync(ExchangeId, user.AuditName);
            if (!outcome.Sent)
            {
                _replayMessage = outcome.Note ?? "The request was not sent.";
                return;
            }

            _replayMessage = $"Replayed: the EKM endpoint answered {outcome.Status}.{(outcome.Note is null ? string.Empty : " " + outcome.Note)}";
            _replayExchangeId = await FindReplayAsync(_record);
        }
        catch (InspectorReplayException exception)
        {
            _replayMessage = exception.Reason switch
            {
                ReplayBlockReason.RevealNotAllowed => "Replay needs the raw request body, which is only kept when reveal is allowed.",
                ReplayBlockReason.BodyNotRetained => "The raw request body of this exchange was not kept.",
                _ => "The exchange is no longer in the inspector.",
            };
        }
        finally
        {
            _replayBusy = false;
        }
    }

    // The replay is the newest exchange of the console test client for the same key and operation after the original.
    private async Task<long?> FindReplayAsync(ExchangeRecord original)
    {
        var filter = new ExchangeFilter { ClientCommonName = ConsoleTestIdentity.CommonName, Key = original.Request.Key, Operation = original.Request.Operation };
        var paging = new ExchangePaging { Limit = 1, AfterId = original.Id };
        var started = Time.GetTimestamp();
        while (Time.GetElapsedTime(started) < TimeSpan.FromSeconds(3))
        {
            var page = Inspector.Query(filter, paging);
            if (page.Items.Count > 0)
            {
                return page.Items[0].Id;
            }

            await Task.Delay(25);
        }

        return null;
    }

    private async Task RevealAsync(string field)
    {
        _revealError = null;
        var user = await CurrentUser.GetAsync();
        try
        {
            _revealed = Inspector.Reveal(ExchangeId, field, user.AuditName);
            _hideTimer?.Dispose();
            _hideTimer = Time.CreateTimer(_ => AutoHide(), null, TimeSpan.FromSeconds(RevealSeconds), Timeout.InfiniteTimeSpan);
        }
        catch (InspectorRevealException exception)
        {
            _revealed = null;
            _revealError = exception.Message;
        }
    }

    private void AutoHide()
    {
        if (_disposed)
        {
            return;
        }

        _ = InvokeAsync(() =>
        {
            HideRevealed();
            StateHasChanged();
        });
    }

    private void HideRevealed()
    {
        _hideTimer?.Dispose();
        _hideTimer = null;
        _revealed = null;
        _revealError = null;
    }

    private static string WaterfallLabel(ExchangeRecord record)
        => $"Timing of exchange {record.Id}: total {ConsoleDisplay.Milliseconds(record.Timing.TotalMs)}, crypto {ConsoleDisplay.Milliseconds(record.Timing.CryptoMs)}, authorization {ConsoleDisplay.Milliseconds(record.Timing.AuthMs)}, injected delay {ConsoleDisplay.Milliseconds(record.Timing.InjectedDelayMs)}, queue wait {ConsoleDisplay.Milliseconds(record.Timing.QueueWaitMs)}.";

    private void BuildWaterfall()
    {
        _segments.Clear();
        if (_record is null)
        {
            return;
        }

        var t = _record.Timing;
        _budgetMs = Limits.Value.LatencyBudgetMs;
        var axis = Math.Max(1, Math.Max(t.TotalMs, _budgetMs) * 1.1);
        var pixelsPerMs = AxisPixels / axis;
        _budgetPx = _budgetMs * pixelsPerMs;

        var stages = new (string Name, string Css, double Ms)[]
        {
            ("Queue wait", "queue", t.QueueWaitMs),
            ("Authorization", "auth", t.AuthMs),
            ("Injected delay", "delay", t.InjectedDelayMs),
            ("Crypto engine", "crypto", t.CryptoMs),
            ("Other (routing, handling)", "other", Math.Max(0, t.TotalMs - t.QueueWaitMs - t.AuthMs - t.InjectedDelayMs - t.CryptoMs)),
        };

        var start = 0d;
        var row = 0;
        foreach (var (name, css, ms) in stages)
        {
            _segments.Add(new WaterfallSegment(name, css, ms, start * pixelsPerMs, ms * pixelsPerMs, row++));
            start += ms;
        }

        _segments.Add(new WaterfallSegment("Total", t.Budget.ToString().ToLowerInvariant(), t.TotalMs, 0, t.TotalMs * pixelsPerMs, row));
    }

    public void Dispose()
    {
        _disposed = true;
        _hideTimer?.Dispose();
    }

    private sealed record WaterfallSegment(string Name, string Css, double Ms, double StartPx, double WidthPx, int Row);
}
