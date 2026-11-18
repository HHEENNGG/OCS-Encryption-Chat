using System.Collections.ObjectModel;
using Avalonia.Threading;
using OCS.App.Infrastructure;
using OCS.Core.Abstractions;
using OCS.Core.Models;

namespace OCS.App.ViewModels;

public sealed class ConversationItem
{
    public required string Id { get; init; }
    public required string DisplayName { get; init; }
    public required string TrustBadge { get; init; }
    public required DateTimeOffset UpdatedAtUtc { get; init; }
}

public sealed class MessageItem
{
    public required string Text { get; init; }
    public required string Caption { get; init; }
    public required bool IsOutgoing { get; init; }

    public static MessageItem From(ChatMessageView v)
    {
        var who = v.Direction == MessageDirection.Outgoing ? "我" : "对方";
        var status = v.LocalStatus == LocalStatus.Copied
            ? "已复制 · 请手动发送(未送达确认)"
            : "已导入并解密";
        return new MessageItem
        {
            Text = v.Text,
            Caption = $"{who} · {v.CreatedAtUtc.ToLocalTime():MM-dd HH:mm} · {status}",
            IsOutgoing = v.Direction == MessageDirection.Outgoing,
        };
    }
}

public sealed class ChatViewModel : ObservableObject, IDisposable
{
    private readonly AppSession _s;
    private readonly MainViewModel _owner;
    private ConversationItem? _selectedConversation;
    private string _composerText = "";
    private string _statusText = "";

    public ChatViewModel(AppSession session, MainViewModel owner)
    {
        _s = session;
        _owner = owner;
        SendCommand = new AsyncRelayCommand(SendAsync);
        ImportNowCommand = new AsyncRelayCommand(ImportNowAsync);
        RefreshCommand = new AsyncRelayCommand(RefreshConversationsAsync);
        _s.Chat.MessageImported += OnMessageImported;
        _s.Chat.ImportRejected += OnImportRejected;
        _s.Chat.ContactsChanged += OnContactsChanged;
        _ = RefreshConversationsAsync();
    }

    public ObservableCollection<ConversationItem> Conversations { get; } = new();
    public ObservableCollection<MessageItem> Messages { get; } = new();
    public AsyncRelayCommand SendCommand { get; }
    public AsyncRelayCommand ImportNowCommand { get; }
    public AsyncRelayCommand RefreshCommand { get; }

    public ConversationItem? SelectedConversation
    {
        get => _selectedConversation;
        set
        {
            if (Set(ref _selectedConversation, value))
            {
                _ = LoadHistoryAsync();
            }
        }
    }

    public string ComposerText
    {
        get => _composerText;
        set => Set(ref _composerText, value);
    }

    public string StatusText
    {
        get => _statusText;
        set => Set(ref _statusText, value);
    }

    private async Task RefreshConversationsAsync()
    {
        try
        {
            var ct = CancellationToken.None;
            var conversations = await _s.Chat.GetConversationsAsync(ct);
            var contacts = (await _s.Chat.GetContactsAsync(ct)).ToDictionary(c => c.Id);
            var selectedId = SelectedConversation?.Id;
            Conversations.Clear();
            foreach (var c in conversations.OrderByDescending(c => c.UpdatedAtUtc))
            {
                var badge = contacts.TryGetValue(c.ContactId, out var contact)
                    ? (contact.TrustState == TrustStates.Verified ? "已验证" : "未验证")
                    : "未知";
                Conversations.Add(new ConversationItem
                {
                    Id = c.Id,
                    DisplayName = c.DisplayName,
                    TrustBadge = badge,
                    UpdatedAtUtc = c.UpdatedAtUtc,
                });
            }
            SelectedConversation = Conversations.FirstOrDefault(c => c.Id == selectedId)
                ?? Conversations.FirstOrDefault();
            if (Conversations.Count == 0)
            {
                StatusText = "还没有会话。请先在「联系人」页导入对方发来的公钥包。";
            }
        }
        catch (Exception e)
        {
            StatusText = "加载会话失败: " + e.Message;
        }
    }

    private async Task LoadHistoryAsync()
    {
        Messages.Clear();
        if (SelectedConversation is not { } conv) return;
        try
        {
            var history = await _s.Chat.LoadHistoryAsync(conv.Id, 500, CancellationToken.None);
            foreach (var v in history)
            {
                Messages.Add(MessageItem.From(v));
            }
        }
        catch (Exception e)
        {
            StatusText = "加载历史失败: " + e.Message;
        }
    }

    private async Task SendAsync()
    {
        _owner.ResetActivity();
        if (SelectedConversation is not { } conv)
        {
            StatusText = "请先选择会话(先在联系人页导入对方的公钥包)。";
            return;
        }
        var text = ComposerText.Trim();
        if (text.Length == 0) return;
        try
        {
            var view = await _s.Chat.SendAsync(conv.Id, text, CancellationToken.None);
            Messages.Add(MessageItem.From(view));
            ComposerText = "";
            StatusText = "已加密并复制到剪贴板 — 请手动粘贴到任意聊天工具发送给对方。";
        }
        catch (CryptoException e)
        {
            StatusText = "发送失败(fail closed): " + e.Message;
        }
        catch (Exception e)
        {
            StatusText = "发送失败: " + e.Message;
        }
    }

    private async Task ImportNowAsync()
    {
        _owner.ResetActivity();
        try
        {
            var text = await _s.Clipboard.ReadTextAsync(CancellationToken.None);
            if (string.IsNullOrEmpty(text))
            {
                StatusText = "剪贴板为空。请先复制对方发来的 OCS 密文。";
                return;
            }
            var ok = await _s.Chat.ImportFromClipboardAsync(text, CancellationToken.None);
            StatusText = ok
                ? "已导入并解密一条消息。"
                : "剪贴板中没有可导入的新 OCS 密文(可能已导入过、是自己复制的、或格式不符)。";
        }
        catch (Exception e)
        {
            StatusText = "导入失败: " + e.Message;
        }
    }

    private void OnMessageImported(ChatMessageView view)
    {
        Dispatcher.UIThread.Post(() =>
        {
            if (SelectedConversation?.Id == view.ConversationId)
            {
                Messages.Add(MessageItem.From(view));
                StatusText = "收到一条新消息(自动从剪贴板导入)。";
            }
            else
            {
                StatusText = "其他会话收到一条新消息。";
            }
            _ = RefreshConversationsAsync();
        });
    }

    private void OnImportRejected(string reason)
    {
        Dispatcher.UIThread.Post(() => StatusText = "剪贴板导入被拒绝: " + reason);
    }

    private void OnContactsChanged()
    {
        Dispatcher.UIThread.Post(() => _ = RefreshConversationsAsync());
    }

    public void Dispose()
    {
        _s.Chat.MessageImported -= OnMessageImported;
        _s.Chat.ImportRejected -= OnImportRejected;
        _s.Chat.ContactsChanged -= OnContactsChanged;
        Messages.Clear();
        ComposerText = "";
    }
}
