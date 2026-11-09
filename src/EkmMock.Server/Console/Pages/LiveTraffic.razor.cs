using EkmMock.Server.Inspector;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.Extensions.Options;
using Microsoft.JSInterop;

namespace EkmMock.Server.WebConsole.Pages;

/// <summary>The Live traffic page (spec 8.5.1): a bounded, filtered, pausable, newest-first stream of exchanges and connection events.</summary>
public sealed partial class LiveTraffic : IAsyncDisposable
{
    private const float RowHeight = 38;

    private static readonly ExchangeFilter EmptyFilter = new();
    private static readonly Choice AllOperations = new(null, "All operations");
    private static readonly Choice AllStatuses = new(null, "All statuses");

    private static readonly Choice[] OperationChoices =
    [
        AllOperations,
        new("info", "info"),
        new("metadata", "metadata"),
        new("wrapkey", "wrapkey"),
        new("unwrapkey", "unwrapkey"),
    ];

    private static readonly Choice[] StatusChoices =
    [
        AllStatuses,
        new("2", "2xx success"),
        new("4", "4xx client error"),
        new("5", "5xx server error"),
    ];

    private readonly CancellationTokenSource _stop = new();
    private InspectorSubscription? _subscription;
    private Task _pump = Task.CompletedTask;
    private LiveTrafficModel? _model;
    private long _renderedVersion = -1;
    private long _feedDropped;
    private bool _autoScroll = true;
    private long? _selectedId;
    private ElementReference _scroller;

    private Choice _operation = AllOperations;
    private Choice _status = AllStatuses;
    private string _namespace = string.Empty;
    private string _key = string.Empty;
    private string _clientCn = string.Empty;
    private string _text = string.Empty;
    private bool _onlyErrors;
    private bool _onlyOverBudget;
    private bool _hideInfo;

    [Inject]
    private IInspector Inspector { get; set; } = default!;

    [Inject]
    private IOptions<ConsoleOptions> Options { get; set; } = default!;

    [Inject]
    private TimeProvider Time { get; set; } = default!;

    [Inject]
    private IJSRuntime Js { get; set; } = default!;

    private LiveTrafficModel Model => _model ??= new LiveTrafficModel(Inspector, Options.Value.LiveTraffic, Time);

    private LiveRow[] Rows => Model.Snapshot();

    private int Cap => Options.Value.LiveTraffic.MaxRows;

    /// <summary>A choice of a select: <see cref="Value"/> null means "no filter".</summary>
    private sealed record Choice(string? Value, string Label);

    protected override void OnInitialized()
    {
        // One subscription per circuit (this component), unsubscribed in DisposeAsync when the page or the circuit ends. It is bounded and drop-oldest
        // (Inspector:SubscriberCapacity), so a browser that cannot keep up only loses its own oldest items.
        _subscription = Inspector.Feed.Subscribe(new InspectorSubscriptionOptions { IncludeConnectionEvents = true });
        Model.Load();
        _pump = Task.Run(() => PumpAsync(_stop.Token));
    }

    /// <summary>
    /// The 1-second guarantee (spec 14 test 20): the feed delivers an exchange to this subscription as soon as the inspector consumer has stored it. The pump takes everything that is
    /// available, renders once, and then waits at most <see cref="LiveTrafficOptions.RenderIntervalMs"/> (default 150 ms, validated to stay below 900 ms) before it looks again. An exchange
    /// that arrives while the pump is idle is rendered at once; one that arrives during the wait is rendered when the wait ends; under a flood each render shows a whole batch.
    /// </summary>
    private async Task PumpAsync(CancellationToken cancellationToken)
    {
        var reader = _subscription!.Reader;
        var interval = TimeSpan.FromMilliseconds(Options.Value.LiveTraffic.RenderIntervalMs);
        try
        {
            while (await reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
            {
                var changed = false;
                await InvokeAsync(() =>
                {
                    while (reader.TryRead(out var item))
                    {
                        changed |= Model.Apply(item);
                    }

                    _feedDropped = _subscription.Dropped;
                }).ConfigureAwait(false);

                if (changed)
                {
                    await InvokeAsync(StateHasChanged).ConfigureAwait(false);
                }

                await Task.Delay(interval, Time, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // The page was left.
        }
        catch (ObjectDisposedException)
        {
            // The circuit ended.
        }
    }

    protected override async Task OnAfterRenderAsync(bool firstRender)
    {
        if (_autoScroll && _renderedVersion != Model.Version)
        {
            _renderedVersion = Model.Version;
            try
            {
                await Js.InvokeVoidAsync("ekmConsole.scrollToTop", _scroller);
            }
            catch (Exception exception) when (exception is JSException or InvalidOperationException or JSDisconnectedException or TaskCanceledException)
            {
                // The scroll position is a nicety.
            }
        }
    }

    private void TogglePause()
    {
        if (Model.Paused)
        {
            Model.Resume();
        }
        else
        {
            Model.Pause();
        }
    }

    private void ClearView()
    {
        Model.Clear();
        _selectedId = null;
    }

    private void SetAutoScroll(bool value) => _autoScroll = value;

    private void SetShowConnections(bool value) => Model.ShowConnectionEvents = value;

    private void Select(long exchangeId) => _selectedId = exchangeId;

    private void CloseDetail() => _selectedId = null;

    private void OnRowKey(KeyboardEventArgs e, long exchangeId)
    {
        if (e.Key is "Enter" or " ")
        {
            Select(exchangeId);
        }
    }

    private void OnOperationChanged(Choice choice) => Apply(() => _operation = choice);

    private void OnStatusChanged(Choice choice) => Apply(() => _status = choice);

    private void OnNamespaceChanged(string? value) => Apply(() => _namespace = value ?? string.Empty);

    private void OnKeyChanged(string? value) => Apply(() => _key = value ?? string.Empty);

    private void OnClientCnChanged(string? value) => Apply(() => _clientCn = value ?? string.Empty);

    private void OnTextChanged(string? value) => Apply(() => _text = value ?? string.Empty);

    private void OnOnlyErrorsChanged(bool value) => Apply(() => _onlyErrors = value);

    private void OnOnlyOverBudgetChanged(bool value) => Apply(() => _onlyOverBudget = value);

    private void OnHideInfoChanged(bool value) => Apply(() => _hideInfo = value);

    private void ResetFilters()
        => Apply(() =>
        {
            _operation = AllOperations;
            _status = AllStatuses;
            _namespace = _key = _clientCn = _text = string.Empty;
            _onlyErrors = _onlyOverBudget = _hideInfo = false;
        });

    private void Apply(Action change)
    {
        change();
        Model.SetFilter(BuildFilter());
    }

    private ExchangeFilter BuildFilter() => new()
    {
        Operation = _operation.Value,
        StatusClass = _status.Value switch
        {
            "2" => StatusClass.Success,
            "4" => StatusClass.ClientError,
            "5" => StatusClass.ServerError,
            _ => null,
        },
        Namespace = Blank(_namespace),
        Key = Blank(_key),
        ClientCommonName = Blank(_clientCn),
        Text = Blank(_text),
        OnlyErrors = _onlyErrors,
        OnlyOverBudget = _onlyOverBudget,
        HideInfo = _hideInfo,
    };

    private static string? Blank(string value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync().ConfigureAwait(false);
        _subscription?.Dispose();
        try
        {
            await _pump.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Expected.
        }

        _stop.Dispose();
    }
}
