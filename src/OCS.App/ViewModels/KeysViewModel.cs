using OCS.App.Infrastructure;
using OCS.Core.Abstractions;

namespace OCS.App.ViewModels;

public sealed class KeysViewModel : ObservableObject, IDisposable
{
    private readonly AppSession _s;
    private readonly MainViewModel _owner;
    private string _localFingerprint = "";
    private int _otpkCount;
    private string _statusText = "";

    public KeysViewModel(AppSession session, MainViewModel owner)
    {
        _s = session;
        _owner = owner;
        ExportBundleCommand = new AsyncRelayCommand(ExportBundleAsync);
        SaveBundleCommand = new AsyncRelayCommand(SaveBundleAsync);
        RefreshCommand = new AsyncRelayCommand(RefreshAsync);
        _ = RefreshAsync();
    }

    public AsyncRelayCommand ExportBundleCommand { get; }
    public AsyncRelayCommand SaveBundleCommand { get; }
    public AsyncRelayCommand RefreshCommand { get; }

    public string LocalFingerprint
    {
        get => _localFingerprint;
        set => Set(ref _localFingerprint, value);
    }

    public int OtpkCount
    {
        get => _otpkCount;
        set => Set(ref _otpkCount, value);
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
            var ct = CancellationToken.None;
            LocalFingerprint = await _s.Chat.GetLocalFingerprintAsync(ct);
            OtpkCount = await _s.Chat.CountAvailableOneTimePreKeysAsync(ct);
        }
        catch (Exception e)
        {
            StatusText = "加载密钥信息失败: " + e.Message;
        }
    }

    private async Task ExportBundleAsync()
    {
        _owner.ResetActivity();
        try
        {
            var bundle = await _s.Chat.ExportBundleAsync(CancellationToken.None);
            await _s.Clipboard.WriteTextAsync(bundle, CancellationToken.None);
            StatusText = "新公钥包已复制到剪贴板(仅公钥)。每次导出生成全新的一次性预密钥批次;旧批次中已被对方使用的密钥不会复用。";
            await RefreshAsync();
        }
        catch (Exception e)
        {
            StatusText = "导出失败: " + e.Message;
        }
    }

    private async Task SaveBundleAsync()
    {
        _owner.ResetActivity();
        try
        {
            var bundle = await _s.Chat.ExportBundleAsync(CancellationToken.None);
            var path = await PickerHelper.SaveTextFileAsync(
                _owner.TopLevelAccessor(), "保存我的公钥包", "my-ocs-bundle.json");
            if (path is null) return;
            await PickerHelper.WriteAllTextAsync(path, bundle, CancellationToken.None);
            StatusText = "公钥包已保存: " + path;
            await RefreshAsync();
        }
        catch (Exception e)
        {
            StatusText = "保存失败: " + e.Message;
        }
    }

    public void Dispose()
    {
        LocalFingerprint = "";
        StatusText = "";
    }
}
