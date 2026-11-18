namespace OCS.Core.Models;

public enum MessageDirection { Incoming, Outgoing }

public static class TrustStates
{
    public const string Unverified = "unverified";
    public const string Verified = "verified";
}

public static class LocalStatus
{
    // "Copied" means ONLY that local encryption + clipboard copy succeeded.
    // It never means delivered or read — there is no server and no network.
    public const string Copied = "copied";
    public const string Imported = "imported";
}

public sealed record ContactRecord(
    string Id,
    string DisplayName,
    string IdentityFingerprint,
    byte[] IdentityPublicKey,
    string TrustState,
    DateTimeOffset CreatedAtUtc);

public sealed record ConversationRecord(
    string Id,
    string ContactId,
    string DisplayName,
    string ProtocolId,
    byte[]? StateBlob,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc);

// EncryptedPayload holds the sealed OCS envelope text; Plaintext is the
// application-layer-encrypted message body for in-memory history rendering.
// Neither is ever stored as plaintext.
public sealed record StoredMessage(
    string MessageId,
    string ConversationId,
    byte[] EncryptedPayload,
    DateTimeOffset CreatedAtUtc,
    MessageDirection Direction,
    string LocalStatus,
    string EnvelopeHash,
    string? Plaintext);

public sealed record SecurityEventRecord(
    string Id,
    string EventType,
    byte[] DetailsEnc,
    DateTimeOffset CreatedAtUtc);

public sealed record ChatMessageView(
    string MessageId,
    string ConversationId,
    MessageDirection Direction,
    string Text,
    DateTimeOffset CreatedAtUtc,
    string LocalStatus);
