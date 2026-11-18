using System.Threading.Channels;
using OCS.Core.Abstractions;
using OCS.Services.Messaging;

namespace OCS.Services.Clipboard;

// Wires clipboard change events into the import pipeline. The clipboard
// adapter never decrypts; this coordinator only forwards text to ChatService,
// which applies the size/type guards, strict envelope parsing, self-write
// suppression and replay dedup. A bounded channel keeps only the LATEST text
// while an import is in flight, so rapid clipboard changes never queue up
// unbounded work and never re-enter the pipeline concurrently.
public sealed class ClipboardImportCoordinator : IAsyncDisposable
{
    private readonly IClipboardService _clipboard;
    private readonly ChatService _chat;
    private readonly Channel<string> _queue;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _consumer;
    private int _disposed;

    public ClipboardImportCoordinator(IClipboardService clipboard, ChatService chat)
    {
        _clipboard = clipboard;
        _chat = chat;
        _queue = Channel.CreateBounded<string>(new BoundedChannelOptions(1)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
            SingleWriter = false,
        });
        _consumer = Task.Run(() => ConsumeAsync(_cts.Token));
        _clipboard.TextChanged += OnTextChanged;
    }

    private void OnTextChanged(string text)
    {
        if (Volatile.Read(ref _disposed) != 0) return;
        _queue.Writer.TryWrite(text);
    }

    private async Task ConsumeAsync(CancellationToken ct)
    {
        try
        {
            await foreach (var text in _queue.Reader.ReadAllAsync(ct))
            {
                try
                {
                    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    timeout.CancelAfter(TimeSpan.FromSeconds(60));
                    await _chat.ImportFromClipboardAsync(text, timeout.Token);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception)
                {
                    // Import failures must never crash the clipboard watcher.
                    // ChatService records security events for rejected envelopes.
                }
            }
        }
        catch (OperationCanceledException)
        {
            // normal shutdown
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _clipboard.TextChanged -= OnTextChanged;
        _queue.Writer.TryComplete();
        _cts.Cancel();
        try
        {
            await _consumer.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
        _cts.Dispose();
        await _clipboard.StopMonitoringAsync(CancellationToken.None).ConfigureAwait(false);
    }
}
