using OCS.App.Infrastructure;
using OCS.Core.Abstractions;
using OCS.Core.Models;

namespace OCS.App.ViewModels;

public sealed class SettingsViewModel : ObservableObject, IDisposable
{
    private readonly AppSession _s;
    private readonly MainViewModel _owner;
    private string _backupPassword = "";
    private string _restorePassword = "";
    private string _statusText = "";

    public SettingsViewModel(AppSession session, MainViewModel owner)
    {
        _s = session;
        _owner = owner;
        CreateBackupCommand = new AsyncRelayCommand(CreateBackupAsync);
        RestoreBackupCommand = new AsyncRelayCommand(RestoreBackupAsync);
    }

    public AsyncRelayCommand CreateBackupCommand { get; }
    public AsyncRelayCommand RestoreBackupCommand { get; }

    public int AutoLockMinutes
    {
        get => _owner.AutoLockMinutes;
        set => _owner.AutoLockMinutes = value;
    }

    public string VaultDirectory => _owner.VaultDirectory;

    public string AboutText =>
        "OCS Encryption Chat — 离线优先剪贴板加密聊天。\n" +
        "协议:Signal PQXDH + Double Ratchet(libsignal 0.108.0,官方实现,经 Rust FFI 边界调用)。\n" +
        "存储:SQLCipher 加密数据库 + 应用层 XChaCha20Poly1305;主密码经 Argon2id 派生包装密钥。\n" +
        "无服务器、无账号、无网络请求。密文经剪贴板人工传递;「已复制」不代表已送达。\n" +
        "本软件未经独立安全审计,请勿用于真实敏感通信。";

    public string BackupPassword
    {
        get => _backupPassword;
        set => Set(ref _backupPassword, value);
    }

    public string RestorePassword
    {
        get => _restorePassword;
        set => Set(ref _restorePassword, value);
    }

    public string StatusText
    {
        get => _statusText;
        set => Set(ref _statusText, value);
    }

    private async Task CreateBackupAsync()
    {
        _owner.ResetActivity();
        var password = BackupPassword;
        if (password.Length < 8)
        {
            StatusText = "请输入至少 8 位的备份密码(建议与主密码相同,恢复时需要)。";
            return;
        }
        try
        {
            var path = await PickerHelper.SaveTextFileAsync(
                _owner.TopLevelAccessor(), "创建加密备份", "ocs-backup-" + DateTime.Now.ToString("yyyyMMdd") + ".ocsbackup");
            if (path is null) return;
            await _s.Backup.CreateAsync(password, path, CancellationToken.None);
            BackupPassword = "";
            StatusText = "加密备份已创建: " + path;
        }
        catch (CryptoException e)
        {
            StatusText = "备份失败: " + e.Message;
        }
        catch (Exception e)
        {
            StatusText = "备份失败: " + e.Message;
        }
    }

    private async Task RestoreBackupAsync()
    {
        _owner.ResetActivity();
        var password = RestorePassword;
        if (password.Length == 0)
        {
            StatusText = "请输入备份密码(创建备份时使用的密码)。";
            return;
        }
        string? path;
        try
        {
            path = await PickerHelper.OpenTextFileAsync(
                _owner.TopLevelAccessor(), "选择加密备份文件", "*.ocsbackup", "*.json");
        }
        catch (Exception e)
        {
            StatusText = "选择文件失败: " + e.Message;
            return;
        }
        if (path is null) return;

        // Restore atomically replaces the active vault. The current session is
        // disposed first; on success a fresh session is opened automatically.
        try
        {
            await _owner.RestoreVaultAsync(path, password);
        }
        catch (CryptoException e)
        {
            _owner.Unlock.ResetForLock("备份恢复被拒绝(fail closed,活动数据未受影响): " + e.Message);
        }
        catch (Exception e)
        {
            _owner.Unlock.ResetForLock("备份恢复失败: " + e.Message);
        }
    }

    public void Dispose()
    {
        BackupPassword = "";
        RestorePassword = "";
        StatusText = "";
    }
}
