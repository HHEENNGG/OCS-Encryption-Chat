using OCS.Core.Abstractions;
using OCS.Core.Models;
using OCS.Services.Crypto;
using OCS.Services.Messaging;
using OCS.Services.Storage;

namespace OCS.Tests;

// In-memory clipboard double: records every write so tests can deliver
// envelopes explicitly (the real adapter polls the OS clipboard).
internal sealed class FakeClipboard : IClipboardService
{
    public string? LastWritten { get; private set; }
    public List<string> Writes { get; } = new();
    public event Action<string>? TextChanged;

    public Task<string?> ReadTextAsync(CancellationToken ct) => Task.FromResult(LastWritten);

    public Task WriteTextAsync(string text, CancellationToken ct)
    {
        LastWritten = text;
        Writes.Add(text);
        TextChanged?.Invoke(text);
        return Task.CompletedTask;
    }

    public Task StartMonitoringAsync(CancellationToken ct) => Task.CompletedTask;
    public Task StopMonitoringAsync(CancellationToken ct) => Task.CompletedTask;
}

// One independent endpoint = one vault directory (SQLCipher db + vault.meta).
internal sealed class TestVault : IAsyncDisposable
{
    public const string Password = "test-master-password-123";

    public required string Dir { get; init; }
    public required VaultService Vault { get; init; }
    public required SqlCipherRepository Repo { get; init; }
    public required ChatService Chat { get; init; }
    public required FakeClipboard Clipboard { get; init; }
    public required BackupService Backup { get; init; }

    public static async Task<TestVault> CreateAsync()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ocs-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var crypto = new RustCryptoEngine();
        var vault = new VaultService(crypto, dir);
        var keys = await vault.CreateAsync(Password, CancellationToken.None);
        var repo = new SqlCipherRepository(crypto, vault.DatabasePath, keys);
        await repo.InitializeAsync(CancellationToken.None);
        var clipboard = new FakeClipboard();
        var chat = new ChatService(crypto, repo, clipboard);
        await chat.EnsureIdentityAsync(CancellationToken.None);
        return new TestVault
        {
            Dir = dir, Vault = vault, Repo = repo, Chat = chat,
            Clipboard = clipboard, Backup = new BackupService(crypto, vault, repo),
        };
    }

    public async ValueTask DisposeAsync()
    {
        await Chat.DisposeAsync();
        await Repo.DisposeAsync();
        try { Directory.Delete(Dir, recursive: true); } catch { /* best effort */ }
    }
}

internal static class TestFlow
{
    // Manual public-bundle exchange + out-of-band fingerprint verification,
    // exactly as docs/KEY-EXCHANGE.md prescribes. Returns both conversations.
    public static async Task<(ConversationRecord AliceConv, ConversationRecord BobConv)> PairAsync(
        TestVault alice, TestVault bob)
    {
        var ct = CancellationToken.None;
        var bundleA = await alice.Chat.ExportBundleAsync(ct);
        var bundleB = await bob.Chat.ExportBundleAsync(ct);
        var contactA = await bob.Chat.ImportContactBundleAsync("Alice", bundleA, ct);
        var contactB = await alice.Chat.ImportContactBundleAsync("Bob", bundleB, ct);
        var fpA = await alice.Chat.GetLocalFingerprintAsync(ct);
        var fpB = await bob.Chat.GetLocalFingerprintAsync(ct);
        await bob.Chat.VerifyContactAsync(contactA.Id, fpA, ct);
        await alice.Chat.VerifyContactAsync(contactB.Id, fpB, ct);
        var aliceConv = (await alice.Chat.GetConversationsAsync(ct)).Single();
        var bobConv = (await bob.Chat.GetConversationsAsync(ct)).Single();
        return (aliceConv, bobConv);
    }

    public static bool ContainsBytes(byte[] haystack, byte[] needle)
    {
        for (var i = 0; i <= haystack.Length - needle.Length; i++)
        {
            var found = true;
            for (var j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j]) { found = false; break; }
            }
            if (found) return true;
        }
        return false;
    }
}
