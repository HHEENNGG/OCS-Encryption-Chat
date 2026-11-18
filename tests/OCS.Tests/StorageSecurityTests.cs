using System.Text;
using OCS.Core.Abstractions;
using OCS.Core.Models;
using OCS.Services.Crypto;
using OCS.Services.Messaging;
using OCS.Services.Storage;
using Xunit;

namespace OCS.Tests;

// Storage / vault / backup security invariants (TEST-PLAN matrix).
public class StorageSecurityTests
{
    private readonly CancellationToken _ct = CancellationToken.None;

    [Fact]
    public async Task WrongMasterPassword_FailsClosed()
    {
        await using var vault = await TestVault.CreateAsync();
        var fresh = new VaultService(new RustCryptoEngine(), vault.Dir);
        var ex = await Assert.ThrowsAsync<CryptoException>(
            () => fresh.OpenAsync("definitely-the-wrong-password", _ct));
        Assert.Equal("wrong_password", ex.ErrorCode);
    }

    [Fact]
    public async Task AtRest_NoPlaintextMessageOrPassword_Anywhere()
    {
        await using var vault = await TestVault.CreateAsync();
        await using var peer = await TestVault.CreateAsync();
        var (conv, peerConv) = await TestFlow.PairAsync(vault, peer);

        const string secret = "绝密内容-UNIQUE-PLAINTEXT-NEEDLE-98765";
        await peer.Chat.SendAsync(peerConv.Id, secret, _ct);
        Assert.True(await vault.Chat.ImportFromClipboardAsync(peer.Clipboard.LastWritten!, _ct));
        await vault.Chat.SendAsync(conv.Id, secret + "-回复", _ct);

        var backupPath = Path.Combine(vault.Dir, "test.ocsbackup");
        await vault.Backup.CreateAsync(TestVault.Password, backupPath, _ct);

        // Dispose so all WAL content is checkpointed into the main file.
        await vault.Chat.DisposeAsync();
        await vault.Repo.DisposeAsync();

        var needleMsg = Encoding.UTF8.GetBytes(secret);
        var needlePw = Encoding.UTF8.GetBytes(TestVault.Password);
        foreach (var file in Directory.GetFiles(vault.Dir))
        {
            var bytes = await File.ReadAllBytesAsync(file, _ct);
            Assert.False(TestFlow.ContainsBytes(bytes, needleMsg), $"plaintext message found in {file}");
            Assert.False(TestFlow.ContainsBytes(bytes, needlePw), $"master password found in {file}");
        }

        // SQLCipher file must not carry the plaintext SQLite header magic.
        var dbHeader = new byte[16];
        await using (var fs = File.OpenRead(vault.Vault.DatabasePath))
        {
            await fs.ReadExactlyAsync(dbHeader, _ct);
        }
        Assert.NotEqual("SQLite format 3\0"u8.ToArray(), dbHeader);
    }

    [Fact]
    public async Task CorruptBackup_Rejected_ActiveDataUntouched()
    {
        await using var vault = await TestVault.CreateAsync();
        await using var peer = await TestVault.CreateAsync();
        var (conv, peerConv) = await TestFlow.PairAsync(vault, peer);
        await peer.Chat.SendAsync(peerConv.Id, "备份前的消息", _ct);
        Assert.True(await vault.Chat.ImportFromClipboardAsync(peer.Clipboard.LastWritten!, _ct));

        var backupPath = Path.Combine(vault.Dir, "good.ocsbackup");
        await vault.Backup.CreateAsync(TestVault.Password, backupPath, _ct);
        var dbBefore = await ReadSharedAsync(vault.Vault.DatabasePath, _ct);

        var corruptPath = Path.Combine(vault.Dir, "corrupt.ocsbackup");
        var corrupt = await File.ReadAllBytesAsync(backupPath, _ct);
        corrupt[corrupt.Length / 2] ^= 0xFF;
        await File.WriteAllBytesAsync(corruptPath, corrupt, _ct);

        // Restore target: a fresh empty directory (no live repository there).
        var targetDir = Path.Combine(Path.GetTempPath(), "ocs-tests-restore-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(targetDir);
        try
        {
            var targetVault = new VaultService(new RustCryptoEngine(), targetDir);
            var backup = new BackupService(new RustCryptoEngine(), targetVault, null);
            var ex = await Assert.ThrowsAsync<CryptoException>(
                () => backup.RestoreAsync(corruptPath, TestVault.Password, _ct));
            Assert.StartsWith("backup_", ex.ErrorCode, StringComparison.Ordinal);
            Assert.False(File.Exists(targetVault.DatabasePath));

            // Active database bytes are unchanged by the rejected restore.
            var dbAfter = await ReadSharedAsync(vault.Vault.DatabasePath, _ct);
            Assert.Equal(dbBefore, dbAfter);
        }
        finally
        {
            try { Directory.Delete(targetDir, true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public async Task BackupRestore_RoundTripsFullHistory()
    {
        await using var vault = await TestVault.CreateAsync();
        await using var peer = await TestVault.CreateAsync();
        var (conv, peerConv) = await TestFlow.PairAsync(vault, peer);
        for (var i = 0; i < 3; i++)
        {
            await peer.Chat.SendAsync(peerConv.Id, $"历史消息 {i}", _ct);
            Assert.True(await vault.Chat.ImportFromClipboardAsync(peer.Clipboard.LastWritten!, _ct));
        }
        var originalHistory = await vault.Chat.LoadHistoryAsync(conv.Id, 100, _ct);

        var backupPath = Path.Combine(vault.Dir, "roundtrip.ocsbackup");
        await vault.Backup.CreateAsync(TestVault.Password, backupPath, _ct);

        var targetDir = Path.Combine(Path.GetTempPath(), "ocs-tests-restore-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(targetDir);
        try
        {
            var targetVault = new VaultService(new RustCryptoEngine(), targetDir);
            var backup = new BackupService(new RustCryptoEngine(), targetVault, null);
            await backup.RestoreAsync(backupPath, TestVault.Password, _ct);

            var keys = await targetVault.OpenAsync(TestVault.Password, _ct);
            var repo = new SqlCipherRepository(new RustCryptoEngine(), targetVault.DatabasePath, keys);
            await repo.InitializeAsync(_ct);
            var chat = new ChatService(new RustCryptoEngine(), repo, new FakeClipboard());
            var restored = await chat.LoadHistoryAsync(conv.Id, 100, _ct);
            Assert.Equal(originalHistory.Count, restored.Count);
            Assert.Equal(originalHistory.Select(m => m.Text), restored.Select(m => m.Text));
            await chat.DisposeAsync();
            await repo.DisposeAsync();
        }
        finally
        {
            try { Directory.Delete(targetDir, true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public async Task WrongBackupPassword_Rejected()
    {
        await using var vault = await TestVault.CreateAsync();
        var backupPath = Path.Combine(vault.Dir, "pw.ocsbackup");
        await vault.Backup.CreateAsync(TestVault.Password, backupPath, _ct);

        var targetDir = Path.Combine(Path.GetTempPath(), "ocs-tests-restore-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(targetDir);
        try
        {
            var targetVault = new VaultService(new RustCryptoEngine(), targetDir);
            var backup = new BackupService(new RustCryptoEngine(), targetVault, null);
            await Assert.ThrowsAsync<CryptoException>(
                () => backup.RestoreAsync(backupPath, "wrong-backup-password", _ct));
            Assert.False(File.Exists(targetVault.DatabasePath));
        }
        finally
        {
            try { Directory.Delete(targetDir, true); } catch { /* best effort */ }
        }
    }

    // SQLCipher keeps the database file open while the repository is live;
    // read it with a permissive share mode instead of File.ReadAllBytes.
    private static async Task<byte[]> ReadSharedAsync(string path, CancellationToken ct)
    {
        await using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        var buffer = new byte[fs.Length];
        await fs.ReadExactlyAsync(buffer, ct);
        return buffer;
    }
}
