using OCS.Core.Abstractions;

namespace OCS.Platform.Clipboard;

// Deliberately non-functional placeholder. Implement separately for Windows,
// X11/Wayland Linux, and macOS; do not poll or retain arbitrary clipboard history.
public sealed class ClipboardServicePlaceholder : IClipboardService
{
    // Kept as a deliberate reference placeholder; the live adapter is
    // AvaloniaClipboardService. The event is part of the interface contract.
#pragma warning disable CS0067
    public event Action<string>? TextChanged;
#pragma warning restore CS0067
    public Task<string?> ReadTextAsync(CancellationToken ct) =>
        throw new NotImplementedException("Platform clipboard adapter is not implemented.");
    public Task WriteTextAsync(string text, CancellationToken ct) =>
        throw new NotImplementedException("Platform clipboard adapter is not implemented.");
    public Task StartMonitoringAsync(CancellationToken ct) =>
        throw new NotImplementedException("Platform clipboard adapter is not implemented.");
    public Task StopMonitoringAsync(CancellationToken ct) => Task.CompletedTask;
}
