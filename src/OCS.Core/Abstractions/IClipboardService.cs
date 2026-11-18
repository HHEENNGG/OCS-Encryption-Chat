namespace OCS.Core.Abstractions;

public interface IClipboardService
{
    event Action<string>? TextChanged;
    Task<string?> ReadTextAsync(CancellationToken ct);
    Task WriteTextAsync(string text, CancellationToken ct);
    Task StartMonitoringAsync(CancellationToken ct);
    Task StopMonitoringAsync(CancellationToken ct);
}
