namespace OCS.Core.Models;

public sealed record MessageEnvelope(
    string Format,
    int Version,
    string ConversationHint,
    string MessageId,
    string PayloadBase64);
