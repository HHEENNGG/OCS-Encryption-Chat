using OCS.Core.Models;

namespace OCS.Core.Abstractions;

// Implementations MUST use an audited encrypted database (SQLCipher) plus
// application-layer AEAD for sensitive columns, and MUST fail closed.
// There is no plaintext SQLite fallback (ADR-004).
public interface IEncryptedRepository : IAsyncDisposable
{
    string DatabasePath { get; }
    Task InitializeAsync(CancellationToken ct);

    // Contacts
    Task<ContactRecord> AddContactAsync(string displayName, string identityFingerprint, byte[] identityPublicKey, CancellationToken ct);
    Task<IReadOnlyList<ContactRecord>> GetContactsAsync(CancellationToken ct);
    Task<ContactRecord?> GetContactAsync(string contactId, CancellationToken ct);
    Task SetContactTrustAsync(string contactId, string trustState, CancellationToken ct);
    Task SetContactDisplayNameAsync(string contactId, string displayName, CancellationToken ct);

    // Conversations
    Task<ConversationRecord> CreateConversationAsync(string contactId, string displayName, string protocolId, CancellationToken ct);
    Task<IReadOnlyList<ConversationRecord>> GetConversationsAsync(CancellationToken ct);
    Task<ConversationRecord?> GetConversationAsync(string conversationId, CancellationToken ct);
    Task SaveConversationStateAsync(string conversationId, byte[] stateBlob, CancellationToken ct);

    // Messages: the message row and the updated protocol state commit in ONE
    // transaction; ciphertext is never exposed before the state is durable.
    Task SaveMessageWithStateAsync(StoredMessage message, byte[]? newStateBlob, uint? consumedOneTimePreKeyId, CancellationToken ct);
    Task<IReadOnlyList<StoredMessage>> GetMessagesAsync(string conversationId, int limit, CancellationToken ct);
    Task<bool> EnvelopeHashExistsAsync(string envelopeHash, CancellationToken ct);

    // Local identity + pre-key material (wrapped blobs)
    Task SaveIdentityAsync(byte[] identityKeyPairBlob, uint registrationId, CancellationToken ct);
    Task<(byte[] IdentityKeyPair, uint RegistrationId)?> LoadIdentityAsync(CancellationToken ct);
    Task SaveSignedPreKeyAsync(uint id, byte[] recordBlob, CancellationToken ct);
    Task SaveKyberPreKeyAsync(uint id, byte[] recordBlob, CancellationToken ct);
    Task SaveOneTimePreKeysAsync(IReadOnlyList<PreKeyEntry> entries, CancellationToken ct);
    Task<IReadOnlyList<PreKeyEntry>> GetSignedPreKeysAsync(CancellationToken ct);
    Task<IReadOnlyList<PreKeyEntry>> GetKyberPreKeysAsync(CancellationToken ct);
    Task<IReadOnlyList<PreKeyEntry>> GetAvailableOneTimePreKeysAsync(CancellationToken ct);
    Task<int> CountAvailableOneTimePreKeysAsync(CancellationToken ct);
    Task<uint> NextPreKeyIdAsync(CancellationToken ct);

    // Exchange package audit trail
    Task RecordExchangePackageAsync(string peerId, string packageHash, int packageVersion, string status, CancellationToken ct);
    Task<bool> ExchangePackageExistsAsync(string packageHash, CancellationToken ct);

    // Security events + settings (values encrypted)
    Task AddSecurityEventAsync(string eventType, string detailsJson, CancellationToken ct);
    Task<IReadOnlyList<SecurityEventRecord>> GetSecurityEventsAsync(int limit, CancellationToken ct);
    Task SetSettingAsync(string key, string valueJson, CancellationToken ct);
    Task<string?> GetSettingAsync(string key, CancellationToken ct);

    // Encrypted snapshot for authenticated backup archives
    Task<byte[]> CreateSnapshotAsync(CancellationToken ct);
}
