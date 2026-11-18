using Avalonia.Controls;
using Avalonia.Input.Platform;
using Avalonia.Threading;
using OCS.Core.Abstractions;

namespace OCS.Platform.Clipboard;

// Avalonia clipboard adapter. It only moves text; it NEVER parses or decrypts
// envelopes (that belongs to the application layer). Monitoring is a modest
// poll (~700 ms) of the text format only — no arbitrary clipboard history is
// retained. Writes made by this adapter are remembered so the monitor does
// not echo them back as change events (first line of self-write suppression;
// ChatService adds a content-hash window as the second line).
public sealed class AvaloniaClipboardService : IClipboardService, IAsyncDisposable
{
    private const int PollIntervalMs = 700;
    private const int MaxObservedTextLength = 2_000_000;

    private readonly Func<TopLevel?> _topLevelProvider;
    private readonly object _sync = new();
    private CancellationTokenSource? _monitorCts;
    private Task? _monitorTask;
    private string? _lastSeen;
    private string? _lastWritten;

    public event Action<string>? TextChanged;

    public AvaloniaClipboardService(Func<TopLevel?> topLevelProvider)
    {
        _topLevelProvider = topLevelProvider;
    }

    private IClipboard? Clipboard => _topLevelProvider()?.Clipboard;

    public async Task<string?> ReadTextAsync(CancellationToken ct)
    {
        var clipboard = Clipboard;
        if (clipboard is null) return null;
        try
        {
            if (Dispatcher.UIThread.CheckAccess())
            {
                return await clipboard.TryGetTextAsync();
            }
            return await Dispatcher.UIThread.InvokeAsync(async () => await clipboard.TryGetTextAsync());
        }
        catch (Exception)
        {
            // Platform clipboard can be transiently unavailable (e.g. Wayland
            // without a focused surface). Treat as "no text", never crash.
            return null;
        }
    }

    public async Task WriteTextAsync(string text, CancellationToken ct)
    {
        var clipboard = Clipboard ?? throw new InvalidOperationException(
            "No window clipboard is available yet.");
        lock (_sync)
        {
            _lastWritten = text;
            _lastSeen = text;
        }
        if (Dispatcher.UIThread.CheckAccess())
        {
            await clipboard.SetTextAsync(text);
        }
        else
        {
            await Dispatcher.UIThread.InvokeAsync(async () => await clipboard.SetTextAsync(text));
        }
    }

    public Task StartMonitoringAsync(CancellationToken ct)
    {
        lock (_sync)
        {
            if (_monitorTask is not null) return Task.CompletedTask;
            _monitorCts = new CancellationTokenSource();
            _monitorTask = Task.Run(() => MonitorLoopAsync(_monitorCts.Token));
        }
        return Task.CompletedTask;
    }

    public async Task StopMonitoringAsync(CancellationToken ct)
    {
        Task? task;
        CancellationTokenSource? cts;
        lock (_sync)
        {
            task = _monitorTask;
            cts = _monitorCts;
            _monitorTask = null;
            _monitorCts = null;
        }
        if (task is null) return;
        cts!.Cancel();
        try
        {
            await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
        cts.Dispose();
    }

    private async Task MonitorLoopAsync(CancellationToken ct)
    {
        try
        {
            var baseline = await ReadTextAsync(ct);
            lock (_sync)
            {
                _lastSeen ??= baseline;
            }
            using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(PollIntervalMs));
            while (await timer.WaitForNextTickAsync(ct))
            {
                var text = await ReadTextAsync(ct);
                if (text is null) continue;
                string? lastSeen, lastWritten;
                lock (_sync)
                {
                    lastSeen = _lastSeen;
                    lastWritten = _lastWritten;
                }
                if (text == lastSeen) continue;
                lock (_sync)
                {
                    _lastSeen = text;
                }
                if (text == lastWritten) continue;      // our own write
                if (text.Length > MaxObservedTextLength) continue; // oversized guard
                TextChanged?.Invoke(text);
            }
        }
        catch (OperationCanceledException)
        {
            // normal shutdown
        }
    }

    public async ValueTask DisposeAsync()
    {
        await StopMonitoringAsync(CancellationToken.None).ConfigureAwait(false);
    }
}
