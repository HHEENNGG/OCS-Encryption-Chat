using System.Text.Json;
using OCS.Core.Abstractions;
using OCS.Core.Models;
using OCS.Services.Clipboard;
using OCS.Services.Crypto;
using OCS.Services.Messaging;
using OCS.Services.Storage;
using Xunit;

namespace OCS.Tests;

// End-to-end protocol flows between two independent offline vaults,
// covering the TEST-PLAN acceptance matrix.
public class ProtocolFlowTests
{
    private readonly CancellationToken _ct = CancellationToken.None;

    [Fact]
    public async Task DuplexConversation_BundleExchange_RatchetAdvances()
    {
        await using var alice = await TestVault.CreateAsync();
        await using var bob = await TestVault.CreateAsync();
        var (aliceConv, bobConv) = await TestFlow.PairAsync(alice, bob);

        // First message uses a one-time pre-key (PQXDH session establishment).
        await bob.Chat.SendAsync(bobConv.Id, "你好 Alice,第一条离线加密消息。", _ct);
        Assert.True(await alice.Chat.ImportFromClipboardAsync(bob.Clipboard.LastWritten!, _ct));

        await alice.Chat.SendAsync(aliceConv.Id, "收到 Bob!", _ct);
        Assert.True(await bob.Chat.ImportFromClipboardAsync(alice.Clipboard.LastWritten!, _ct));

        for (var i = 0; i < 3; i++)
        {
            await bob.Chat.SendAsync(bobConv.Id, $"往返 {i}", _ct);
            Assert.True(await alice.Chat.ImportFromClipboardAsync(bob.Clipboard.LastWritten!, _ct));
            await alice.Chat.SendAsync(aliceConv.Id, $"应答 {i}", _ct);
            Assert.True(await bob.Chat.ImportFromClipboardAsync(alice.Clipboard.LastWritten!, _ct));
        }

        var aliceHistory = await alice.Chat.LoadHistoryAsync(aliceConv.Id, 100, _ct);
        var bobHistory = await bob.Chat.LoadHistoryAsync(bobConv.Id, 100, _ct);
        Assert.Equal(8, aliceHistory.Count);
        Assert.Equal(8, bobHistory.Count);
        Assert.Contains(aliceHistory, m => m.Text == "你好 Alice,第一条离线加密消息。");
        Assert.Contains(bobHistory, m => m.Text == "收到 Bob!");
        // Outbound status is "copied", never delivered/read.
        Assert.All(aliceHistory.Where(m => m.Direction == MessageDirection.Outgoing),
            m => Assert.Equal(LocalStatus.Copied, m.LocalStatus));
    }

    [Fact]
    public async Task FirstPrekeyMessage_ConsumesExactlyOneOtpk()
    {
        await using var alice = await TestVault.CreateAsync();
        await using var bob = await TestVault.CreateAsync();
        var (_, bobConv) = await TestFlow.PairAsync(alice, bob);

        var before = await alice.Chat.CountAvailableOneTimePreKeysAsync(_ct);
        await bob.Chat.SendAsync(bobConv.Id, "消耗一个一次性预密钥", _ct);
        Assert.True(await alice.Chat.ImportFromClipboardAsync(bob.Clipboard.LastWritten!, _ct));
        var after = await alice.Chat.CountAvailableOneTimePreKeysAsync(_ct);
        Assert.Equal(before - 1, after);

        // Subsequent ratchet messages must NOT consume more OTPKs.
        await bob.Chat.SendAsync(bobConv.Id, "第二条", _ct);
        Assert.True(await alice.Chat.ImportFromClipboardAsync(bob.Clipboard.LastWritten!, _ct));
        Assert.Equal(after, await alice.Chat.CountAvailableOneTimePreKeysAsync(_ct));
    }

    [Fact]
    public async Task ReplayedEnvelope_IsRejected_NoDuplicateHistory()
    {
        await using var alice = await TestVault.CreateAsync();
        await using var bob = await TestVault.CreateAsync();
        var (aliceConv, bobConv) = await TestFlow.PairAsync(alice, bob);

        await bob.Chat.SendAsync(bobConv.Id, "只此一条", _ct);
        var envelope = bob.Clipboard.LastWritten!;
        Assert.True(await alice.Chat.ImportFromClipboardAsync(envelope, _ct));
        Assert.False(await alice.Chat.ImportFromClipboardAsync(envelope, _ct));
        // Self-write suppression: Bob never imports his own envelope.
        Assert.False(await bob.Chat.ImportFromClipboardAsync(envelope, _ct));

        var history = await alice.Chat.LoadHistoryAsync(aliceConv.Id, 100, _ct);
        Assert.Single(history);
    }

    [Fact]
    public async Task TamperedCiphertext_IsRejected()
    {
        await using var alice = await TestVault.CreateAsync();
        await using var bob = await TestVault.CreateAsync();
        var (_, bobConv) = await TestFlow.PairAsync(alice, bob);

        await bob.Chat.SendAsync(bobConv.Id, "即将被篡改", _ct);
        var envelope = bob.Clipboard.LastWritten!;
        Assert.True(CipherDetector.TryParse(envelope, out var parsed));
        var payload = Convert.FromBase64String(parsed!.PayloadBase64);
        payload[^1] ^= 0xFF; // break the AEAD tag
        var tampered = CipherDetector.BuildEnvelope(parsed.ConversationHint, parsed.MessageId, payload);
        Assert.False(await alice.Chat.ImportFromClipboardAsync(tampered, _ct));
    }

    [Fact]
    public async Task ConcurrentSends_SerializeAndBothDeliver()
    {
        await using var alice = await TestVault.CreateAsync();
        await using var bob = await TestVault.CreateAsync();
        var (aliceConv, bobConv) = await TestFlow.PairAsync(alice, bob);

        var writesBefore = bob.Clipboard.Writes.Count;
        var t1 = bob.Chat.SendAsync(bobConv.Id, "并发 A", _ct);
        var t2 = bob.Chat.SendAsync(bobConv.Id, "并发 B", _ct);
        await Task.WhenAll(t1, t2);
        var newEnvelopes = bob.Clipboard.Writes.Skip(writesBefore).ToList();
        Assert.Equal(2, newEnvelopes.Count);
        Assert.True(await alice.Chat.ImportFromClipboardAsync(newEnvelopes[0], _ct));
        Assert.True(await alice.Chat.ImportFromClipboardAsync(newEnvelopes[1], _ct));

        var history = await alice.Chat.LoadHistoryAsync(aliceConv.Id, 100, _ct);
        Assert.Contains(history, m => m.Text == "并发 A");
        Assert.Contains(history, m => m.Text == "并发 B");
    }

    [Fact]
    public async Task FingerprintMismatch_NeverMarksVerified()
    {
        await using var alice = await TestVault.CreateAsync();
        await using var bob = await TestVault.CreateAsync();
        var bundleB = await bob.Chat.ExportBundleAsync(_ct);
        var contact = await alice.Chat.ImportContactBundleAsync("Bob", bundleB, _ct);
        Assert.Equal(TrustStates.Unverified, contact.TrustState);

        var fpAlice = await alice.Chat.GetLocalFingerprintAsync(_ct); // wrong fingerprint
        var ex = await Assert.ThrowsAsync<CryptoException>(
            () => alice.Chat.VerifyContactAsync(contact.Id, fpAlice, _ct));
        Assert.Equal("fingerprint_mismatch", ex.ErrorCode);

        var still = (await alice.Chat.GetContactsAsync(_ct)).Single(c => c.Id == contact.Id);
        Assert.Equal(TrustStates.Unverified, still.TrustState);
    }

    [Fact]
    public async Task TamperedBundle_IsRejected()
    {
        await using var alice = await TestVault.CreateAsync();
        await using var bob = await TestVault.CreateAsync();
        var bundleJson = await bob.Chat.ExportBundleAsync(_ct);

        using var doc = JsonDocument.Parse(bundleJson);
        var dict = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(doc.RootElement.GetRawText())!;
        var signed = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(dict["signedPreKey"].GetRawText())!;
        var sig = Convert.FromBase64String(signed["signature"].GetString()!);
        sig[0] ^= 0xFF;
        var tamperedBundle = new Dictionary<string, object?>
        {
            ["protocol"] = dict["protocol"].GetString(),
            ["formatVersion"] = dict["formatVersion"].GetInt32(),
            ["registrationId"] = dict["registrationId"].GetInt32(),
            ["deviceId"] = dict["deviceId"].GetInt32(),
            ["identityPublicKey"] = dict["identityPublicKey"].GetString(),
            ["fingerprint"] = dict["fingerprint"].GetString(),
            ["signedPreKey"] = new Dictionary<string, object?>
            {
                ["id"] = signed["id"].GetInt32(),
                ["publicKey"] = signed["publicKey"].GetString(),
                ["signature"] = Convert.ToBase64String(sig),
            },
            ["kyberPreKey"] = dict["kyberPreKey"],
            ["oneTimePreKeys"] = dict["oneTimePreKeys"],
            ["createdAtUtc"] = dict["createdAtUtc"].GetString(),
            ["expiresAtUtc"] = dict["expiresAtUtc"].GetString(),
        };
        await Assert.ThrowsAsync<CryptoException>(
            () => alice.Chat.ImportContactBundleAsync("Mallory", JsonSerializer.Serialize(tamperedBundle), _ct));
        Assert.Empty(await alice.Chat.GetContactsAsync(_ct));
    }

    [Fact]
    public async Task Restart_PersistsRatchetStateAndHistory()
    {
        await using var alice = await TestVault.CreateAsync();
        await using var bob = await TestVault.CreateAsync();
        var (aliceConv, bobConv) = await TestFlow.PairAsync(alice, bob);

        await bob.Chat.SendAsync(bobConv.Id, "重启前的消息", _ct);
        Assert.True(await alice.Chat.ImportFromClipboardAsync(bob.Clipboard.LastWritten!, _ct));

        // Simulate process restart: brand-new repository + chat service on the
        // same encrypted files (old instances stay undisposed = "hard" exit).
        var crypto = new RustCryptoEngine();
        var keys = await alice.Vault.OpenAsync(TestVault.Password, _ct);
        var repo2 = new SqlCipherRepository(crypto, alice.Vault.DatabasePath, keys);
        await repo2.InitializeAsync(_ct);
        var chat2 = new ChatService(crypto, repo2, new FakeClipboard());

        var history = await chat2.LoadHistoryAsync(aliceConv.Id, 100, _ct);
        Assert.Contains(history, m => m.Text == "重启前的消息");

        // Ratchet state survived: the conversation continues seamlessly.
        await bob.Chat.SendAsync(bobConv.Id, "重启后的消息", _ct);
        Assert.True(await chat2.ImportFromClipboardAsync(bob.Clipboard.LastWritten!, _ct));

        await chat2.DisposeAsync();
        await repo2.DisposeAsync();
    }

    [Fact]
    public async Task OversizedAndMalformedClipboardText_SafelyIgnored()
    {
        await using var alice = await TestVault.CreateAsync();
        Assert.False(await alice.Chat.ImportFromClipboardAsync(new string('A', 2_500_000), _ct));
        Assert.False(await alice.Chat.ImportFromClipboardAsync(
            "-----BEGIN OCS ENCRYPTED MESSAGE-----\nOCS-Version: 99\nPayload: !!!\n-----END OCS ENCRYPTED MESSAGE-----", _ct));
        Assert.False(await alice.Chat.ImportFromClipboardAsync("just some copied text", _ct));
    }
}
