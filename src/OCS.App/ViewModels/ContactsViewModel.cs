using System.Collections.ObjectModel;
using Avalonia.Threading;
using OCS.App.Infrastructure;
using OCS.Core.Abstractions;
using OCS.Core.Models;

namespace OCS.App.ViewModels;

public sealed class ContactsViewModel : ObservableObject, IDisposable
{
    private readonly AppSession _s;
    private readonly MainViewModel _owner;
    private ContactRecord? _selectedContact;
    private string _importName = "";
    private string _importBundleText = "";
    private string _verifyFingerprint = "";
    private string _statusText = "";

    public ContactsViewModel(AppSession session, MainViewModel owner)
    {
        _s = session;
        _owner = owner;
        ImportCommand = new AsyncRelayCommand(ImportAsync);
        ImportFileCommand = new AsyncRelayCommand(ImportFileAsync);
        VerifyCommand = new AsyncRelayCommand(VerifyAsync);
        ExportMyBundleCommand = new AsyncRelayCommand(ExportMyBundleAsync);
        SaveMyBundleCommand = new AsyncRelayCommand(SaveMyBundleAsync);
        RefreshCommand = new AsyncRelayCommand(RefreshAsync);
        _s.Chat.ContactsChanged += OnContactsChanged;
        _ = RefreshAsync();
    }

    public ObservableCollection<ContactRecord> Contacts { get; } = new();
    public AsyncRelayCommand ImportCommand { get; }
    public AsyncRelayCommand ImportFileCommand { get; }
    public AsyncRelayCommand VerifyCommand { get; }
    public AsyncRelayCommand ExportMyBundleCommand { get; }
    public AsyncRelayCommand SaveMyBundleCommand { get; }
    public AsyncRelayCommand RefreshCommand { get; }

    public ContactRecord? SelectedContact
    {
        get => _selectedContact;
        set => Set(ref _selectedContact, value);
    }

    public string ImportName
    {
        get => _importName;
        set => Set(ref _importName, value);
    }

    public string ImportBundleText
    {
        get => _importBundleText;
        set => Set(ref _importBundleText, value);
    }

    public string VerifyFingerprint
    {
        get => _verifyFingerprint;
        set => Set(ref _verifyFingerprint, value);
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
            var selectedId = SelectedContact?.Id;
            var list = await _s.Chat.GetContactsAsync(CancellationToken.None);
            Contacts.Clear();
            foreach (var c in list) Contacts.Add(c);
            SelectedContact = Contacts.FirstOrDefault(c => c.Id == selectedId) ?? Contacts.FirstOrDefault();
        }
        catch (Exception e)
        {
            StatusText = "加载联系人失败: " + e.Message;
        }
    }

    private async Task ImportAsync()
    {
        _owner.ResetActivity();
        var name = ImportName.Trim();
        var bundle = ImportBundleText.Trim();
        if (name.Length == 0 || bundle.Length == 0)
        {
            StatusText = "请填写联系人名称并粘贴对方的公钥包 JSON。";
            return;
        }
        await ImportCoreAsync(name, bundle);
    }

    private async Task ImportFileAsync()
    {
        _owner.ResetActivity();
        try
        {
            var content = await PickerHelper.OpenTextFileAsync(
                _owner.TopLevelAccessor(), "选择对方的公钥包文件", "*.json", "*.ocsbundle", "*.txt");
            if (content is null) return;
            var name = ImportName.Trim();
            if (name.Length == 0) name = "联系人 " + (Contacts.Count + 1);
            await ImportCoreAsync(name, content.Trim());
        }
        catch (Exception e)
        {
            StatusText = "读取文件失败: " + e.Message;
        }
    }

    private async Task ImportCoreAsync(string name, string bundleJson)
    {
        try
        {
            var contact = await _s.Chat.ImportContactBundleAsync(name, bundleJson, CancellationToken.None);
            ImportBundleText = "";
            StatusText = $"已导入「{contact.DisplayName}」,当前状态:未验证。请通过电话/见面等可信渠道核对指纹后再确认。";
            await RefreshAsync();
            SelectedContact = Contacts.FirstOrDefault(c => c.Id == contact.Id);
        }
        catch (CryptoException e)
        {
            StatusText = "导入被拒绝(fail closed): " + e.Message;
        }
        catch (Exception e)
        {
            StatusText = "导入失败: " + e.Message;
        }
    }

    private async Task VerifyAsync()
    {
        _owner.ResetActivity();
        if (SelectedContact is not { } contact)
        {
            StatusText = "请先选择联系人。";
            return;
        }
        var fp = VerifyFingerprint.Trim();
        if (fp.Length == 0)
        {
            StatusText = "请输入通过可信渠道(电话/见面)从对方处获得的指纹。";
            return;
        }
        try
        {
            await _s.Chat.VerifyContactAsync(contact.Id, fp, CancellationToken.None);
            VerifyFingerprint = "";
            StatusText = "指纹匹配 — 已标记为「已验证」。";
            await RefreshAsync();
        }
        catch (CryptoException e) when (e.ErrorCode == "fingerprint_mismatch")
        {
            StatusText = "指纹不匹配 — 绝不标记为已验证!可能存在中间人攻击,请通过可信渠道重新核对。";
        }
        catch (Exception e)
        {
            StatusText = "验证失败: " + e.Message;
        }
    }

    private async Task ExportMyBundleAsync()
    {
        _owner.ResetActivity();
        try
        {
            var bundle = await _s.Chat.ExportBundleAsync(CancellationToken.None);
            await _s.Clipboard.WriteTextAsync(bundle, CancellationToken.None);
            StatusText = "我的公钥包已复制到剪贴板(仅公钥,绝不包含私钥)。请发送给对方;每次导出都会生成新的一次性预密钥批次。";
        }
        catch (Exception e)
        {
            StatusText = "导出失败: " + e.Message;
        }
    }

    private async Task SaveMyBundleAsync()
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
        }
        catch (Exception e)
        {
            StatusText = "保存失败: " + e.Message;
        }
    }

    private void OnContactsChanged()
    {
        Dispatcher.UIThread.Post(() => _ = RefreshAsync());
    }

    public void Dispose()
    {
        _s.Chat.ContactsChanged -= OnContactsChanged;
        Contacts.Clear();
        ImportBundleText = "";
        VerifyFingerprint = "";
    }
}
