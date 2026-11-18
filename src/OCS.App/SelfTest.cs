using System.Text;
using System.Text.Json;
using OCS.Core.Abstractions;
using OCS.Core.Models;
using OCS.Services.Clipboard;
using OCS.Services.Crypto;
using OCS.Services.Messaging;
using OCS.Services.Storage;

namespace OCS.App;

// Headless end-to-end verification (TEST-PLAN.md matrix). Runs two independent
// vaults ("Alice" and "Bob") in temp directories, exchanges public bundles,
// chats in both directions, and checks the fail-closed invariants. No network,
// no GUI. Exit code 0 = all checks passed.
internal static class SelfTest
{
    private const string Password = "selftest-master-password-123";

    private sealed class InMemoryClipboard : IClipboardService
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

    private sealed class Endpoint : IAsyncDisposable
    {
        public required string Dir { get; init; }
        public required VaultService Vault { get; init; }
        public required SqlCipherRepository Repo { get; init; }
        public required ChatService Chat { get; init; }
        public required InMemoryClipboard Clipboard { get; init; }
        public required BackupService Backup { get; init; }

        public static async Task<Endpoint> CreateAsync(string dir, ICryptoEngine crypto, CancellationToken ct)
        {
            var vault = new VaultService(crypto, dir);
            var keys = await vault.CreateAsync(Password, ct);
            var repo = new SqlCipherRepository(crypto, vault.DatabasePath, keys);
            await repo.InitializeAsync(ct);
            var clipboard = new InMemoryClipboard();
            var chat = new ChatService(crypto, repo, clipboard);
            await chat.EnsureIdentityAsync(ct);
            return new Endpoint
            {
                Dir = dir, Vault = vault, Repo = repo, Chat = chat,
                Clipboard = clipboard, Backup = new BackupService(crypto, vault, repo),
            };
        }

        public async ValueTask DisposeAsync()
        {
            await Chat.DisposeAsync();
            await Repo.DisposeAsync();
        }
    }

    public static async Task<int> RunAsync()
    {
        var root = Path.Combine(Path.GetTempPath(), "ocs-selftest-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var failures = 0;

        void Check(bool ok, string name)
        {
            Console.WriteLine((ok ? "  [PASS] " : "  [FAIL] ") + name);
            if (!ok) failures++;
        }

        async Task<bool> ThrowsCrypto(Func<Task> action, string codePrefix)
        {
            try
            {
                await action();
                return false;
            }
            catch (CryptoException e)
            {
                return e.ErrorCode.StartsWith(codePrefix, StringComparison.Ordinal);
            }
        }

        try
        {
            var crypto = new RustCryptoEngine();
            var ct = CancellationToken.None;
            Console.WriteLine("OCS self-test: two offline endpoints, manual bundle exchange");

            await using var alice = await Endpoint.CreateAsync(Path.Combine(root, "alice"), crypto, ct);
            await using var bob = await Endpoint.CreateAsync(Path.Combine(root, "bob"), crypto, ct);
            var fpAlice = await alice.Chat.GetLocalFingerprintAsync(ct);
            var fpBob = await bob.Chat.GetLocalFingerprintAsync(ct);
            Check(fpAlice.Length > 0 && fpAlice != fpBob, "identities created with distinct fingerprints");

            // ── bundle exchange ──────────────────────────────────────────────
            var bundleAlice = await alice.Chat.ExportBundleAsync(ct);
            var bundleBob = await bob.Chat.ExportBundleAsync(ct);
            var contactAliceAtBob = await bob.Chat.ImportContactBundleAsync("Alice", bundleAlice, ct);
            var contactBobAtAlice = await alice.Chat.ImportContactBundleAsync("Bob", bundleBob, ct);
            Check(contactAliceAtBob.TrustState == TrustStates.Unverified,
                "imported contact starts UNVERIFIED");

            // Wrong fingerprint FIRST, while the contact is still unverified:
            // a mismatch must throw and must never mark the contact Verified.
            var wrongVerify = await ThrowsCrypto(
                () => alice.Chat.VerifyContactAsync(contactBobAtAlice.Id, fpAlice, ct), "fingerprint_mismatch");
            var stillUnverified = (await alice.Chat.GetContactsAsync(ct)).Single(c => c.Id == contactBobAtAlice.Id);
            Check(wrongVerify && stillUnverified.TrustState == TrustStates.Unverified,
                "fingerprint mismatch NEVER marks Verified");

            await bob.Chat.VerifyContactAsync(contactAliceAtBob.Id, fpAlice, ct);
            await alice.Chat.VerifyContactAsync(contactBobAtAlice.Id, fpBob, ct);
            var verified = (await bob.Chat.GetContactsAsync(ct)).Single(c => c.Id == contactAliceAtBob.Id);
            Check(verified.TrustState == TrustStates.Verified, "out-of-band fingerprint match => Verified");

            // ── tampered bundle rejected ─────────────────────────────────────
            using (var doc = JsonDocument.Parse(bundleAlice))
            {
                var tampered = JsonSerializer.Deserialize<Dictionary<string, object?>>(
                    JsonSerializer.Serialize(doc.RootElement))!;
                // flip a byte in the signed pre-key signature
                var sig = JsonSerializer.Deserialize<Dictionary<string, object?>>(
                    JsonSerializer.Serialize(tampered["signedPreKey"]))!;
                var sigBytes = Convert.FromBase64String(sig["signature"]!.ToString()!);
                sigBytes[0] ^= 0xFF;
                sig["signature"] = Convert.ToBase64String(sigBytes);
                tampered["signedPreKey"] = sig;
                var tamperedJson = JsonSerializer.Serialize(tampered);
                var rejected = await ThrowsCrypto(
                    () => bob.Chat.ImportContactBundleAsync("Mallory", tamperedJson, ct), "crypto_error");
                Check(rejected, "tampered bundle signature => import rejected");
            }

            // ── bidirectional chat ───────────────────────────────────────────
            var convBob = (await bob.Chat.GetConversationsAsync(ct)).Single();
            var convAlice = (await alice.Chat.GetConversationsAsync(ct)).Single();

            var m1 = await bob.Chat.SendAsync(convBob.Id, "你好 Alice,这是第一条离线加密消息。", ct);
            Check(m1.LocalStatus == LocalStatus.Copied, "outbound status is 'copied', never 'delivered'");
            var imported1 = await alice.Chat.ImportFromClipboardAsync(bob.Clipboard.LastWritten!, ct);
            Check(imported1, "Alice decrypts Bob's first (pre-key) message");

            var m2 = await alice.Chat.SendAsync(convAlice.Id, "收到 Bob!双向通道已建立。", ct);
            var imported2 = await bob.Chat.ImportFromClipboardAsync(alice.Clipboard.LastWritten!, ct);
            Check(imported2, "Bob decrypts Alice's reply");

            for (var i = 0; i < 5; i++)
            {
                await bob.Chat.SendAsync(convBob.Id, $"往返消息 {i} — 前向保密棘轮推进。", ct);
                var ok = await alice.Chat.ImportFromClipboardAsync(bob.Clipboard.LastWritten!, ct);
                if (!ok) { Check(false, $"round-trip {i}"); break; }
                await alice.Chat.SendAsync(convAlice.Id, $"应答 {i}", ct);
                ok = await bob.Chat.ImportFromClipboardAsync(alice.Clipboard.LastWritten!, ct);
                if (!ok) { Check(false, $"round-trip reply {i}"); break; }
                if (i == 4) Check(true, "5 round-trips after session confirmation (Double Ratchet)");
            }

            // ── replay / self-write / dedup ──────────────────────────────────
            var lastEnvelope = bob.Clipboard.LastWritten!;
            var replay = await alice.Chat.ImportFromClipboardAsync(lastEnvelope, ct);
            var historyAlice = await alice.Chat.LoadHistoryAsync(convAlice.Id, 1000, ct);
            Check(!replay, "replayed envelope is rejected (no duplicate import)");
            var selfImport = await bob.Chat.ImportFromClipboardAsync(lastEnvelope, ct);
            Check(!selfImport, "own clipboard write never re-imports");

            // ── concurrent sends on one conversation serialize ───────────────
            var writesBefore = bob.Clipboard.Writes.Count;
            var t1 = bob.Chat.SendAsync(convBob.Id, "并发消息 A", ct);
            var t2 = bob.Chat.SendAsync(convBob.Id, "并发消息 B", ct);
            await Task.WhenAll(t1, t2);
            var newEnvelopes = bob.Clipboard.Writes.Skip(writesBefore).ToList();
            Check(newEnvelopes.Count == 2, "two concurrent sends on one conversation both complete");
            var ok1 = await alice.Chat.ImportFromClipboardAsync(newEnvelopes[0], ct);
            var ok2 = await alice.Chat.ImportFromClipboardAsync(newEnvelopes[1], ct);
            Check(ok1 && ok2, "both concurrent messages decrypt (serialized ratchet state)");
            var historyAlice2 = await alice.Chat.LoadHistoryAsync(convAlice.Id, 1000, ct);
            Check(historyAlice2.Count >= 8, "history persisted across imports");

            // ── wrong master password fails closed ───────────────────────────
            var wrongPw = await ThrowsCrypto(
                () => new VaultService(crypto, alice.Dir).OpenAsync("wrong-password-000", ct), "wrong_password");
            Check(wrongPw, "wrong master password => fail closed");

            // ── malformed / oversized clipboard input ignored ────────────────
            var junk = await alice.Chat.ImportFromClipboardAsync(new string('A', 2_500_000), ct);
            var malformed = await alice.Chat.ImportFromClipboardAsync(
                "-----BEGIN OCS ENCRYPTED MESSAGE-----\nOCS-Version: 99\nPayload: !!!\n-----END OCS ENCRYPTED MESSAGE-----", ct);
            Check(!junk && !malformed, "oversized and malformed clipboard text safely ignored");

            // ── no plaintext at rest ─────────────────────────────────────────
            await alice.Repo.DisposeAsync();
            var dbBytes = await File.ReadAllBytesAsync(Path.Combine(alice.Dir, "ocs.db"), ct);
            var needle1 = Encoding.UTF8.GetBytes("你好 Alice");
            var needle2 = Encoding.UTF8.GetBytes(Password);
            Check(!Contains(dbBytes, needle1) && !Contains(dbBytes, needle2),
                "database file contains no plaintext message or master password");
            var metaBytes = await File.ReadAllBytesAsync(Path.Combine(alice.Dir, "vault.meta"), ct);
            Check(!Contains(metaBytes, needle2), "vault metadata contains no master password");
            // re-open for backup step
            var keysA = await alice.Vault.OpenAsync(Password, ct);
            var repoA2 = new SqlCipherRepository(crypto, alice.Vault.DatabasePath, keysA);
            await repoA2.InitializeAsync(ct);
            var backupA = new BackupService(crypto, alice.Vault, repoA2);

            // ── backup / restore ─────────────────────────────────────────────
            var backupPath = Path.Combine(root, "alice.ocsbackup");
            await backupA.CreateAsync(Password, backupPath, ct);
            var backupBytes = await File.ReadAllBytesAsync(backupPath, ct);
            Check(!Contains(backupBytes, needle1), "backup archive contains no plaintext");

            var corruptPath = Path.Combine(root, "corrupt.ocsbackup");
            var corrupt = (byte[])backupBytes.Clone();
            corrupt[corrupt.Length / 2] ^= 0xFF;
            await File.WriteAllBytesAsync(corruptPath, corrupt, ct);
            var dirC = Path.Combine(root, "restored");
            var vaultC = new VaultService(crypto, dirC);
            var backupC = new BackupService(crypto, vaultC, repoA2);
            var corruptRejected = await ThrowsCrypto(
                () => backupC.RestoreAsync(corruptPath, Password, ct), "backup_");
            Check(corruptRejected && !File.Exists(vaultC.DatabasePath),
                "corrupted backup rejected; no database created");

            await repoA2.DisposeAsync();
            await backupC.RestoreAsync(backupPath, Password, ct);
            var keysC = await vaultC.OpenAsync(Password, ct);
            var repoC = new SqlCipherRepository(crypto, vaultC.DatabasePath, keysC);
            await repoC.InitializeAsync(ct);
            var chatC = new ChatService(crypto, repoC, new InMemoryClipboard());
            var restoredHistory = await chatC.LoadHistoryAsync(convAlice.Id, 1000, ct);
            Check(restoredHistory.Count == historyAlice2.Count,
                "restore reproduces full encrypted history");
            await chatC.DisposeAsync();
            await repoC.DisposeAsync();

            Console.WriteLine(failures == 0
                ? "SELFTEST PASS (all checks green)"
                : $"SELFTEST FAIL ({failures} check(s) failed)");
            return failures == 0 ? 0 : 1;
        }
        catch (Exception e)
        {
            Console.WriteLine("SELFTEST CRASH: " + e);
            return 2;
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* best effort */ }
        }
    }

    private static bool Contains(byte[] haystack, byte[] needle)
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
