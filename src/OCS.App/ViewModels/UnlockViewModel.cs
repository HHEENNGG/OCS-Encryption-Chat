using OCS.App.Infrastructure;
using OCS.Core.Abstractions;
using OCS.Core.Models;

namespace OCS.App.ViewModels;

public sealed class UnlockViewModel : ObservableObject
{
    private readonly MainViewModel _owner;
    private string _password = "";
    private string _confirmPassword = "";
    private string _status = "";
    private bool _isBusy;

    public UnlockViewModel(MainViewModel owner)
    {
        _owner = owner;
        SubmitCommand = new AsyncRelayCommand(SubmitAsync);
    }

    public bool IsNewVault => !_owner.VaultExists;
    public AsyncRelayCommand SubmitCommand { get; }

    public string Password
    {
        get => _password;
        set => Set(ref _password, value);
    }

    public string ConfirmPassword
    {
        get => _confirmPassword;
        set => Set(ref _confirmPassword, value);
    }

    public string Status
    {
        get => _status;
        set => Set(ref _status, value);
    }

    public bool IsBusy
    {
        get => _isBusy;
        set => Set(ref _isBusy, value);
    }

    public void ResetForLock(string? message)
    {
        Password = "";
        ConfirmPassword = "";
        Status = message ?? "";
        Raise(nameof(IsNewVault));
    }

    private async Task SubmitAsync()
    {
        Status = "";
        IsBusy = true;
        try
        {
            if (IsNewVault)
            {
                if (Password.Length < 8)
                {
                    Status = "主密码至少需要 8 个字符。";
                    return;
                }
                if (Password != ConfirmPassword)
                {
                    Status = "两次输入的主密码不一致。";
                    return;
                }
                await _owner.CreateVaultAsync(Password);
            }
            else
            {
                await _owner.OpenVaultAsync(Password);
            }
            Password = "";
            ConfirmPassword = "";
        }
        catch (CryptoException e) when (e.ErrorCode == "wrong_password")
        {
            Status = "主密码错误 — 已拒绝解锁(fail closed)。";
        }
        catch (CryptoException e)
        {
            Status = "加密错误: " + e.ErrorCode + " — " + e.Message;
        }
        catch (Exception e)
        {
            Status = "初始化失败: " + e.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }
}
