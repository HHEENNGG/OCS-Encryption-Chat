using Avalonia.Controls;
using Avalonia.Threading;
using OCS.App.Infrastructure;
using OCS.Core.Abstractions;
using OCS.Platform;
using OCS.Platform.Clipboard;
using OCS.Services.Clipboard;
using OCS.Services.Crypto;
using OCS.Services.Messaging;
using OCS.Services.Storage;

namespace OCS.App.ViewModels;

// Everything that exists only while the vault is unlocked. Disposing the
// session clears keys, stops clipboard monitoring and drops all sensitive VMs.
public sealed class AppSession : IAsyncDisposable
{
    public required VaultService Vault { get; init; }
    public required SqlCipherRepository Repo { get; init; }
    public required ChatService Chat { get; init; }
    public required AvaloniaClipboardService Clipboard { get; init; }
    public required ClipboardImportCoordinator ImportCoordinator { get; init; }
    public required BackupService Backup { get; init; }

    public ChatViewModel ChatVm { get; set; } = null!;
    public ContactsViewModel ContactsVm { get; set; } = null!;
    public KeysViewModel KeysVm { get; set; } = null!;
    public SecurityViewModel SecurityVm { get; set; } = null!;
    public SettingsViewModel SettingsVm { get; set; } = null!;

    public async ValueTask DisposeAsync()
    {
        ChatVm.Dispose();
        ContactsVm.Dispose();
        KeysVm.Dispose();
        SecurityVm.Dispose();
        SettingsVm.Dispose();
        await ImportCoordinator.DisposeAsync();
        await Clipboard.DisposeAsync();
        await Chat.DisposeAsync();
        await Repo.DisposeAsync();
    }
}

public sealed class MainViewModel : ObservableObject
{
    private readonly ICryptoEngine _crypto = new RustCryptoEngine();
    private readonly string _vaultDir = AppOptions.DataDirectoryOverride ?? AppPaths.VaultDirectory;
    private readonly DispatcherTimer _idleTimer;
    private AppSession? _session;
    private object? _currentPage;
    private bool _isUnlocked;
    private string _nav = "chat";
    private int _autoLockMinutes = 5;
    private bool _shuttingDown;

    public MainViewModel()
    {
        Unlock = new UnlockViewModel(this);
        _currentPage = Unlock;
        NavCommand = new RelayCommand(p => Nav = p as string ?? "chat");
        LockCommand = new AsyncRelayCommand(() => LockAsync("已手动锁定。"));
        _idleTimer = new DispatcherTimer { Interval = TimeSpan.FromMinutes(_autoLockMinutes) };
        _idleTimer.Tick += async (_, _) =>
        {
            try { await LockAsync("因不活动已自动锁定。"); }
            catch { /* locking must never crash the app */ }
        };
    }

    public UnlockViewModel Unlock { get; }
    public Func<TopLevel?> TopLevelAccessor { get; set; } = () => null;
    public string VaultDirectory => _vaultDir;
    public bool VaultExists => new VaultService(_crypto, _vaultDir).Exists;
    public RelayCommand NavCommand { get; }
    public AsyncRelayCommand LockCommand { get; }

    public bool IsUnlocked
    {
        get => _isUnlocked;
        private set => Set(ref _isUnlocked, value);
    }

    public object? CurrentPage
    {
        get => _currentPage;
        private set => Set(ref _currentPage, value);
    }

    public string Nav
    {
        get => _nav;
        set
        {
            if (Set(ref _nav, value)) Navigate();
        }
    }

    public int AutoLockMinutes
    {
        get => _autoLockMinutes;
        set
        {
            var clamped = Math.Clamp(value, 1, 120);
            if (Set(ref _autoLockMinutes, clamped))
            {
                _idleTimer.Interval = TimeSpan.FromMinutes(clamped);
                _ = PersistAutoLockAsync();
            }
        }
    }

    private async Task PersistAutoLockAsync()
    {
        try
        {
            if (_session is { } s)
            {
                await s.Repo.SetSettingAsync("auto-lock-minutes", _autoLockMinutes.ToString(), CancellationToken.None);
            }
        }
        catch { /* settings persistence is best-effort */ }
    }

    public void ResetActivity()
    {
        if (!_isUnlocked) return;
        _idleTimer.Stop();
        _idleTimer.Start();
    }

    public async Task OpenVaultAsync(string password)
    {
        var vault = new VaultService(_crypto, _vaultDir);
        var keys = await vault.OpenAsync(password, CancellationToken.None);
        await BuildSessionAsync(vault, keys);
    }

    public async Task CreateVaultAsync(string password)
    {
        var vault = new VaultService(_crypto, _vaultDir);
        var keys = await vault.CreateAsync(password, CancellationToken.None);
        await BuildSessionAsync(vault, keys);
    }

    private async Task BuildSessionAsync(VaultService vault, VaultService.VaultKeys keys)
    {
        var ct = CancellationToken.None;
        var repo = new SqlCipherRepository(_crypto, vault.DatabasePath, keys);
        try
        {
            await repo.InitializeAsync(ct);
        }
        catch
        {
            await repo.DisposeAsync();
            throw;
        }

        try
        {
            var clipboard = new AvaloniaClipboardService(() => TopLevelAccessor());
            var chat = new ChatService(_crypto, repo, clipboard);
            await chat.EnsureIdentityAsync(ct);
            var coordinator = new ClipboardImportCoordinator(clipboard, chat);
            var backup = new BackupService(_crypto, vault, repo);

            var session = new AppSession
            {
                Vault = vault, Repo = repo, Chat = chat,
                Clipboard = clipboard, ImportCoordinator = coordinator, Backup = backup,
            };
            session.ChatVm = new ChatViewModel(session, this);
            session.ContactsVm = new ContactsViewModel(session, this);
            session.KeysVm = new KeysViewModel(session, this);
            session.SecurityVm = new SecurityViewModel(session, this);
            session.SettingsVm = new SettingsViewModel(session, this);

            var stored = await repo.GetSettingAsync("auto-lock-minutes", ct);
            if (int.TryParse(stored, out var minutes))
            {
                _autoLockMinutes = Math.Clamp(minutes, 1, 120);
                _idleTimer.Interval = TimeSpan.FromMinutes(_autoLockMinutes);
                Raise(nameof(AutoLockMinutes));
            }

            _session = session;
            await clipboard.StartMonitoringAsync(ct);
            IsUnlocked = true;
            _nav = "chat";
            Raise(nameof(Nav));
            Navigate();
            _idleTimer.Start();
        }
        catch
        {
            await repo.DisposeAsync();
            throw;
        }
    }

    public async Task LockAsync(string? message = null)
    {
        _idleTimer.Stop();
        var session = _session;
        _session = null;
        IsUnlocked = false;
        _nav = "chat";
        Raise(nameof(Nav));
        CurrentPage = Unlock;
        Unlock.ResetForLock(message);
        if (session is not null)
        {
            await session.DisposeAsync();
        }
    }

    public async Task RestoreVaultAsync(string backupPath, string password)
    {
        await LockAsync();
        var vault = new VaultService(_crypto, _vaultDir);
        var backup = new BackupService(_crypto, vault, null);
        await backup.RestoreAsync(backupPath, password, CancellationToken.None);
        await OpenVaultAsync(password);
    }

    public async Task ShutdownAsync()
    {
        if (_shuttingDown) return;
        _shuttingDown = true;
        await LockAsync();
    }

    private void Navigate()
    {
        if (_session is not { } s)
        {
            CurrentPage = Unlock;
            return;
        }
        CurrentPage = _nav switch
        {
            "contacts" => s.ContactsVm,
            "keys" => s.KeysVm,
            "security" => s.SecurityVm,
            "settings" => s.SettingsVm,
            _ => s.ChatVm,
        };
    }
}
