using System.Collections.ObjectModel;
using OCS.App.Infrastructure;
using OCS.Core.Models;

namespace OCS.App.ViewModels;

public sealed class SecurityEventItem
{
    public required SecurityEventRecord Record { get; init; }
    public string EventType => Record.EventType;
    public string TimeText => Record.CreatedAtUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
    public string DetailsText { get; set; } = "(选择后解密显示)";
}

public sealed class SecurityViewModel : ObservableObject, IDisposable
{
    private readonly AppSession _s;
    private readonly MainViewModel _owner;
    private SecurityEventItem? _selectedEvent;
    private bool _monitoringPaused;
    private string _statusText = "剪贴板监视:运行中(仅识别 OCS 密文,不保留任意剪贴板历史)。";

    public SecurityViewModel(AppSession session, MainViewModel owner)
    {
        _s = session;
        _owner = owner;
        RefreshCommand = new AsyncRelayCommand(RefreshAsync);
        ToggleMonitoringCommand = new AsyncRelayCommand(ToggleMonitoringAsync);
        LockNowCommand = new AsyncRelayCommand(() => owner.LockAsync("已手动锁定。"));
        _ = RefreshAsync();
    }

    public ObservableCollection<SecurityEventItem> Events { get; } = new();
    public AsyncRelayCommand RefreshCommand { get; }
    public AsyncRelayCommand ToggleMonitoringCommand { get; }
    public AsyncRelayCommand LockNowCommand { get; }

    public SecurityEventItem? SelectedEvent
    {
        get => _selectedEvent;
        set
        {
            if (Set(ref _selectedEvent, value))
            {
                _ = LoadDetailsAsync();
            }
        }
    }

    public bool MonitoringPaused
    {
        get => _monitoringPaused;
        set => Set(ref _monitoringPaused, value);
    }

    public string StatusText
    {
        get => _statusText;
        set => Set(ref _statusText, value);
    }

    private async Task RefreshAsync()
    {
        try
        {
            var records = await _s.Chat.GetSecurityEventsAsync(200, CancellationToken.None);
            Events.Clear();
            foreach (var r in records)
            {
                Events.Add(new SecurityEventItem { Record = r });
            }
        }
        catch (Exception e)
        {
            StatusText = "加载安全事件失败: " + e.Message;
        }
    }

    private async Task LoadDetailsAsync()
    {
        if (SelectedEvent is not { } item) return;
        try
        {
            var details = await _s.Chat.OpenSecurityEventAsync(item.Record, CancellationToken.None);
            item.DetailsText = details;
            // refresh the selected item display
            var idx = Events.IndexOf(item);
            if (idx >= 0)
            {
                Events[idx] = item;
                SelectedEvent = item;
            }
        }
        catch (Exception e)
        {
            item.DetailsText = "解密失败: " + e.Message;
        }
    }

    private async Task ToggleMonitoringAsync()
    {
        _owner.ResetActivity();
        try
        {
            var ct = CancellationToken.None;
            if (MonitoringPaused)
            {
                await _s.Clipboard.StartMonitoringAsync(ct);
                MonitoringPaused = false;
                StatusText = "剪贴板监视:运行中(仅识别 OCS 密文,不保留任意剪贴板历史)。";
            }
            else
            {
                await _s.Clipboard.StopMonitoringAsync(ct);
                MonitoringPaused = true;
                StatusText = "剪贴板监视:已暂停。仍可在聊天页用「立即导入」手动导入。";
            }
        }
        catch (Exception e)
        {
            StatusText = "切换监视状态失败: " + e.Message;
        }
    }

    public void Dispose()
    {
        Events.Clear();
        SelectedEvent = null;
    }
}
