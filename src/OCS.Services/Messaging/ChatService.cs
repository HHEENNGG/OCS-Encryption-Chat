using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using OCS.Core.Abstractions;
using OCS.Core.Models;
using OCS.Services.Clipboard;

namespace OCS.Services.Messaging;

// Application-layer orchestrator. Owns the workflow rules:
//  - outbound: encrypt -> persist message + ratchet state in ONE transaction
//    -> only then expose ciphertext to the clipboard ("copied", never "sent");
//  - inbound: strict envelope parse -> replay dedup -> authenticated decrypt
//    -> atomic persist -> in-memory rendering only;
//  - per-conversation serialization of protocol operations;
//  - self-write suppression so our own clipboard writes never re-import.
public sealed class ChatService : IAsyncDisposable
{
    public const string LocalName = "ocs-local";
    public const uint LocalDeviceId = 1;
    public const string ProtocolId = "signal-pqxdh";
    private const string IdentityPublicKeySetting = "identity-public-key";
    private const int SelfWriteWindow = 128;

    private readonly ICryptoEngine _crypto;
    private readonly IEncryptedRepository _repo;
    private readonly IClipboardService _clipboard;
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _conversationLocks = new();
    private readonly ConcurrentDictionary<string, byte> _selfWriteHashes = new();
    private readonly SemaphoreSlim _importGate = new(1, 1);

    public event Action<ChatMessageView>? MessageImported;
    public event Action<string>? ImportRejected;
    public event Action? ContactsChanged;

    public ChatService(ICryptoEngine crypto, IEncryptedRepository repo, IClipboardService clipboard)
    {
        _crypto = crypto;
        _repo = repo;
        _clipboard = clipboard;
    }

    // ── identity bootstrap ───────────────────────────────────────────────────

    public async Task<string> EnsureIdentityAsync(CancellationToken ct)
    {
        var existing = await _repo.LoadIdentityAsync(ct);
        if (existing is null)
        {
            var identity = await _crypto.CreateIdentityAsync(ct);
            await _repo.SaveIdentityAsync(identity.IdentityKeyPair, identity.RegistrationId, ct);
            await _repo.SetSettingAsync(IdentityPublicKeySetting,
                JsonSerializer.Serialize(Convert.ToBase64String(identity.IdentityPublicKey)), ct);
            await ExportBundleAsync(ct);
            await _repo.AddSecurityEventAsync("identity_created",
                JsonSerializer.Serialize(new { identity.Fingerprint }), ct);
            return identity.Fingerprint;
        }
        return await GetLocalFingerprintAsync(ct);
    }

    public async Task<string> GetLocalFingerprintAsync(CancellationToken ct)
    {
        var pkJson = await _repo.GetSettingAsync(IdentityPublicKeySetting, ct)
            ?? throw new CryptoException("no_identity", "Local identity has not been created yet.");
        var pk = Convert.FromBase64String(JsonSerializer.Deserialize<string>(pkJson)!);
        return await _crypto.FingerprintAsync(pk, ct);
    }

    // ── bundle export / import ───────────────────────────────────────────────

    // Every export creates a FRESH batch of one-time pre-keys (ids continue the
    // local sequence); previously exported batches stay valid until consumed.
    public async Task<string> ExportBundleAsync(CancellationToken ct)
    {
        var identity = await _repo.LoadIdentityAsync(ct)
            ?? throw new CryptoException("no_identity", "Local identity has not been created yet.");
        var start = await _repo.NextPreKeyIdAsync(ct);
        var created = await _crypto.CreateBundleAsync(new BundleCreationRequest(
            identity.IdentityKeyPair, identity.RegistrationId, LocalDeviceId,
            SignedPreKeyId: start, KyberPreKeyId: start + 1,
            OneTimePreKeyStartId: start + 2, OneTimePreKeyCount: 20, ValidityDays: 30), ct);
        await _repo.SaveSignedPreKeyAsync(start, created.Private.SignedPreKeyRecord, ct);
        await _repo.SaveKyberPreKeyAsync(start + 1, created.Private.KyberPreKeyRecord, ct);
        await _repo.SaveOneTimePreKeysAsync(created.Private.OneTimePreKeys, ct);
        await _repo.AddSecurityEventAsync("bundle_exported",
            JsonSerializer.Serialize(new { oneTimePreKeys = created.Private.OneTimePreKeys.Count }), ct);
        return created.BundleJson;
    }

    public async Task<ContactRecord> ImportContactBundleAsync(string displayName, string bundleJson,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(displayName) || displayName.Length > 128)
        {
            throw new CryptoException("invalid_name", "Contact display name must be 1-128 characters.");
        }
        var validation = await _crypto.ValidateBundleAsync(bundleJson, ct);

        using var doc = JsonDocument.Parse(bundleJson);
        var identityPk = Convert.FromBase64String(
            doc.RootElement.GetProperty("identityPublicKey").GetString()!);

        var packageHash = HashText(bundleJson);
        if (await _repo.ExchangePackageExistsAsync(packageHash, ct))
        {
            throw new CryptoException("duplicate_package", "This exact key package was already imported.");
        }
        foreach (var c in await _repo.GetContactsAsync(ct))
        {
            if (c.IdentityPublicKey.AsSpan().SequenceEqual(identityPk))
            {
                throw new CryptoException("duplicate_identity",
                    "A contact with this identity already exists. Import a fresh package only via a new contact flow.");
            }
        }

        var contact = await _repo.AddContactAsync(displayName.Trim(), validation.Fingerprint, identityPk, ct);
        await _repo.SetSettingAsync($"bundle:{contact.Id}", JsonSerializer.Serialize(bundleJson), ct);
        await _repo.RecordExchangePackageAsync(contact.Id, packageHash, 1, "imported", ct);

        var conversation = await _repo.CreateConversationAsync(contact.Id, displayName.Trim(), ProtocolId, ct);
        await InitiateSessionAsync(conversation, contact, bundleJson, ct);

        await _repo.AddSecurityEventAsync("contact_imported",
            JsonSerializer.Serialize(new { contactId = contact.Id, validation.Fingerprint }), ct);
        ContactsChanged?.Invoke();
        return contact;
    }

    private async Task InitiateSessionAsync(ConversationRecord conversation, ContactRecord contact,
        string bundleJson, CancellationToken ct)
    {
        var identity = await _repo.LoadIdentityAsync(ct)
            ?? throw new CryptoException("no_identity", "Local identity missing.");
        var initiation = await _crypto.InitiateSessionAsync(new SessionInitRequest(
            identity.IdentityKeyPair, identity.RegistrationId,
            LocalName, LocalDeviceId, contact.Id, 1, contact.IdentityPublicKey, bundleJson), ct);
        await _repo.SaveConversationStateAsync(conversation.Id, initiation.SessionRecord, ct);
    }

    // The user compared fingerprints out-of-band and confirms the match.
    // The service re-derives the fingerprint from the pinned public key; a
    // mismatch can NEVER result in a Verified state.
    public async Task VerifyContactAsync(string contactId, string confirmedFingerprint, CancellationToken ct)
    {
        var contact = await _repo.GetContactAsync(contactId, ct)
            ?? throw new CryptoException("no_contact", "Contact not found.");
        var actual = await _crypto.FingerprintAsync(contact.IdentityPublicKey, ct);
        if (!string.Equals(NormalizeFingerprint(actual), NormalizeFingerprint(confirmedFingerprint),
                StringComparison.OrdinalIgnoreCase))
        {
            await _repo.AddSecurityEventAsync("fingerprint_mismatch",
                JsonSerializer.Serialize(new { contactId }), ct);
            throw new CryptoException("fingerprint_mismatch",
                "Fingerprint does not match the pinned identity. Contact stays unverified.");
        }
        await _repo.SetContactTrustAsync(contactId, TrustStates.Verified, ct);
        await _repo.AddSecurityEventAsync("contact_verified",
            JsonSerializer.Serialize(new { contactId }), ct);
        ContactsChanged?.Invoke();
    }

    private static string NormalizeFingerprint(string s) =>
        s.Replace(" ", "").Replace(":", "").ToUpperInvariant();

    // ── outbound ─────────────────────────────────────────────────────────────

    public async Task<ChatMessageView> SendAsync(string conversationId, string plaintext, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(plaintext))
        {
            throw new CryptoException("empty_message", "Message text is empty.");
        }
        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        if (plaintextBytes.Length > 1_000_000)
        {
            throw new CryptoException("message_too_large", "Message exceeds the 1 MB limit.");
        }

        var gate = _conversationLocks.GetOrAdd(conversationId, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(ct);
        try
        {
            var conversation = await _repo.GetConversationAsync(conversationId, ct)
                ?? throw new CryptoException("no_conversation", "Conversation not found.");
            if (conversation.StateBlob is null)
            {
                throw new CryptoException("no_session", "No session state for this conversation.");
            }
            var contact = await _repo.GetContactAsync(conversation.ContactId, ct)
                ?? throw new CryptoException("no_contact", "Contact not found.");
            var identity = await _repo.LoadIdentityAsync(ct)
                ?? throw new CryptoException("no_identity", "Local identity missing.");

            var outcome = await _crypto.EncryptAsync(new EncryptRequest(
                identity.IdentityKeyPair, identity.RegistrationId,
                LocalName, LocalDeviceId, contact.Id, 1, contact.IdentityPublicKey,
                conversation.StateBlob, plaintextBytes), ct);

            var messageId = Guid.NewGuid().ToString("N");
            var typedPayload = new byte[1 + outcome.Ciphertext.Length];
            typedPayload[0] = (byte)outcome.MessageType;
            outcome.Ciphertext.CopyTo(typedPayload.AsSpan(1));
            var envelope = CipherDetector.BuildEnvelope(conversationId, messageId, typedPayload);
            var envelopeHash = HashText(envelope);
            var now = DateTimeOffset.UtcNow;

            // Atomic: message + updated ratchet state commit BEFORE the
            // ciphertext is exposed to the clipboard.
            await _repo.SaveMessageWithStateAsync(new StoredMessage(
                messageId, conversationId, Encoding.UTF8.GetBytes(envelope), now,
                MessageDirection.Outgoing, LocalStatus.Copied, envelopeHash, plaintext),
                outcome.SessionRecord, consumedOneTimePreKeyId: null, ct);

            RememberSelfWrite(envelopeHash);
            await _clipboard.WriteTextAsync(envelope, ct);

            return new ChatMessageView(messageId, conversationId, MessageDirection.Outgoing,
                plaintext, now, LocalStatus.Copied);
        }
        finally
        {
            gate.Release();
        }
    }

    // ── inbound ──────────────────────────────────────────────────────────────

    public async Task<bool> ImportFromClipboardAsync(string text, CancellationToken ct)
    {
        if (!CipherDetector.LooksLikeEnvelope(text)) return false;
        if (_selfWriteHashes.ContainsKey(HashText(text.Trim()))) return false;
        if (!CipherDetector.TryParse(text, out var envelope) || envelope is null) return false;

        await _importGate.WaitAsync(ct);
        try
        {
            var payload = Convert.FromBase64String(envelope.PayloadBase64);
            var canonical = CipherDetector.BuildEnvelope(envelope.ConversationHint, envelope.MessageId, payload);
            var canonicalHash = HashText(canonical);
            if (_selfWriteHashes.ContainsKey(canonicalHash)) return false;
            if (await _repo.EnvelopeHashExistsAsync(canonicalHash, ct)) return false; // replay

            // Prefer the conversation named by the routing hint; fall back to
            // trying every established conversation (hint is not authenticated).
            var candidates = new List<ConversationRecord>();
            var hinted = await _repo.GetConversationAsync(envelope.ConversationHint, ct);
            if (hinted is not null) candidates.Add(hinted);
            foreach (var c in await _repo.GetConversationsAsync(ct))
            {
                if (c.Id != envelope.ConversationHint && c.StateBlob is not null) candidates.Add(c);
            }

            var identity = await _repo.LoadIdentityAsync(ct);
            if (identity is null) return false;
            var signed = await _repo.GetSignedPreKeysAsync(ct);
            var kyber = await _repo.GetKyberPreKeysAsync(ct);
            var otpks = await _repo.GetAvailableOneTimePreKeysAsync(ct);

            foreach (var conversation in candidates)
            {
                var contact = await _repo.GetContactAsync(conversation.ContactId, ct);
                if (contact is null) continue;
                var gate = _conversationLocks.GetOrAdd(conversation.Id, _ => new SemaphoreSlim(1, 1));
                await gate.WaitAsync(ct);
                try
                {
                    DecryptOutcome outcome;
                    try
                    {
                        outcome = await _crypto.DecryptAsync(new DecryptRequest(
                            identity.Value.IdentityKeyPair, identity.Value.RegistrationId,
                            LocalName, LocalDeviceId, contact.Id, 1, contact.IdentityPublicKey,
                            conversation.StateBlob, payload[1..], payload[0],
                            signed, kyber, otpks), ct);
                    }
                    catch (CryptoException)
                    {
                        continue; // wrong conversation or unauthenticated input
                    }

                    var plaintext = Encoding.UTF8.GetString(outcome.Plaintext);
                    var now = DateTimeOffset.UtcNow;
                    await _repo.SaveMessageWithStateAsync(new StoredMessage(
                        envelope.MessageId, conversation.Id, Encoding.UTF8.GetBytes(canonical), now,
                        MessageDirection.Incoming, LocalStatus.Imported, canonicalHash, plaintext),
                        outcome.SessionRecord, outcome.ConsumedOneTimePreKeyId, ct);

                    MessageImported?.Invoke(new ChatMessageView(envelope.MessageId, conversation.Id,
                        MessageDirection.Incoming, plaintext, now, LocalStatus.Imported));
                    return true;
                }
                finally
                {
                    gate.Release();
                }
            }

            await _repo.AddSecurityEventAsync("import_failed",
                JsonSerializer.Serialize(new { envelopeHash = canonicalHash }), ct);
            ImportRejected?.Invoke("检测到 OCS 密文,但无法用任何已建立会话解密(可能来自未导入的联系人或已损坏)。");
            return false;
        }
        finally
        {
            _importGate.Release();
        }
    }

    // ── history / listings ───────────────────────────────────────────────────

    public async Task<IReadOnlyList<ChatMessageView>> LoadHistoryAsync(string conversationId, int limit,
        CancellationToken ct)
    {
        var stored = await _repo.GetMessagesAsync(conversationId, limit, ct);
        return stored.Select(m => new ChatMessageView(m.MessageId, m.ConversationId, m.Direction,
            m.Plaintext ?? "[历史消息无法解密]", m.CreatedAtUtc, m.LocalStatus)).ToList();
    }

    public Task<IReadOnlyList<ContactRecord>> GetContactsAsync(CancellationToken ct) =>
        _repo.GetContactsAsync(ct);

    public Task<IReadOnlyList<ConversationRecord>> GetConversationsAsync(CancellationToken ct) =>
        _repo.GetConversationsAsync(ct);

    public Task<int> CountAvailableOneTimePreKeysAsync(CancellationToken ct) =>
        _repo.CountAvailableOneTimePreKeysAsync(ct);

    public Task<IReadOnlyList<SecurityEventRecord>> GetSecurityEventsAsync(int limit, CancellationToken ct) =>
        _repo.GetSecurityEventsAsync(limit, ct);

    public async Task<string> OpenSecurityEventAsync(SecurityEventRecord record, CancellationToken ct)
    {
        // Details are encrypted at rest; decryption happens in memory only.
        var vaultDek = _repo is SqlCipherRepositoryAccess access ? access.Dek : null;
        if (vaultDek is null)
        {
            throw new InvalidOperationException("Repository does not expose column decryption.");
        }
        return Encoding.UTF8.GetString(await _crypto.OpenAsync(vaultDek, record.DetailsEnc,
            Encoding.UTF8.GetBytes($"ocs-col-v1:event:{record.Id}"), ct));
    }

    // ── self-write suppression ───────────────────────────────────────────────

    private void RememberSelfWrite(string envelopeHash)
    {
        if (_selfWriteHashes.Count >= SelfWriteWindow)
        {
            _selfWriteHashes.Clear();
        }
        _selfWriteHashes[envelopeHash] = 0;
    }

    public static string HashText(string text) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));

    public async ValueTask DisposeAsync()
    {
        foreach (var gate in _conversationLocks.Values) gate.Dispose();
        _importGate.Dispose();
        await ValueTask.CompletedTask;
    }
}

// Small seam so the UI can decrypt security-event details without the
// repository interface exposing the raw DEK to everyone.
public interface SqlCipherRepositoryAccess
{
    byte[] Dek { get; }
}
