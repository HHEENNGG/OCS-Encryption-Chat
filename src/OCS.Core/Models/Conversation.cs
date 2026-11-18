namespace OCS.Core.Models;

public sealed record Conversation(
    string Id,
    string ContactId,
    string DisplayName,
    string ProtocolId,
    DateTimeOffset CreatedAtUtc,
    bool IdentityVerified);
