using OCS.Core.Models;

namespace OCS.Services.Clipboard;

// Strict, versioned parser for the OCS clipboard envelope. The clipboard is an
// untrusted channel: anything malformed, oversized, or of an unknown version
// is rejected without side effects. The payload stays opaque here — only the
// protocol adapter may interpret it.
public static class CipherDetector
{
    public const string BeginMarker = "-----BEGIN OCS ENCRYPTED MESSAGE-----";
    public const string EndMarker = "-----END OCS ENCRYPTED MESSAGE-----";
    public const string FormatName = "ocs-envelope";
    public const int SupportedVersion = 1;
    public const int MaxTextLength = 2_000_000;
    public const int MaxPayloadBase64Length = 1_500_000;
    public const int MaxPayloadBytes = 1_000_001; // 1 type byte + <=1MB ciphertext

    public static bool LooksLikeEnvelope(string? text) =>
        text is not null && text.Length <= MaxTextLength &&
        text.Contains(BeginMarker, StringComparison.Ordinal);

    public static bool TryParse(string? text, out MessageEnvelope? envelope)
    {
        envelope = null;
        if (text is null || text.Length == 0 || text.Length > MaxTextLength) return false;

        var trimmed = text.Trim();
        if (!trimmed.StartsWith(BeginMarker, StringComparison.Ordinal) ||
            !trimmed.EndsWith(EndMarker, StringComparison.Ordinal)) return false;

        var lines = trimmed.Replace("\r\n", "\n").Split('\n');
        if (lines.Length != 6) return false;
        if (lines[0] != BeginMarker || lines[5] != EndMarker) return false;

        if (!TryHeader(lines[1], "OCS-Version", out var versionStr) ||
            !TryHeader(lines[2], "OCS-Conversation", out var convHint) ||
            !TryHeader(lines[3], "OCS-Message-Id", out var messageId) ||
            !TryHeader(lines[4], "Payload", out var payloadB64)) return false;

        if (versionStr != "1") return false;
        if (!IsSafeToken(convHint) || !IsSafeToken(messageId)) return false;
        if (payloadB64.Length == 0 || payloadB64.Length > MaxPayloadBase64Length) return false;
        if (!IsStrictBase64(payloadB64)) return false;

        byte[] payload;
        try
        {
            payload = Convert.FromBase64String(payloadB64);
        }
        catch (FormatException)
        {
            return false;
        }
        if (payload.Length < 2 || payload.Length > MaxPayloadBytes) return false;
        if (payload[0] != 2 && payload[0] != 3) return false; // Whisper / PreKey only

        envelope = new MessageEnvelope(FormatName, SupportedVersion, convHint, messageId, payloadB64);
        return true;
    }

    public static string BuildEnvelope(string conversationId, string messageId, byte[] typedPayload)
    {
        if (!IsSafeToken(conversationId) || !IsSafeToken(messageId))
        {
            throw new ArgumentException("Envelope identifiers must be safe tokens.");
        }
        return string.Join("\n",
            BeginMarker,
            "OCS-Version: 1",
            $"OCS-Conversation: {conversationId}",
            $"OCS-Message-Id: {messageId}",
            $"Payload: {Convert.ToBase64String(typedPayload)}",
            EndMarker);
    }

    private static bool TryHeader(string line, string name, out string value)
    {
        value = "";
        var prefix = name + ": ";
        if (!line.StartsWith(prefix, StringComparison.Ordinal)) return false;
        value = line[prefix.Length..];
        return value.Length > 0 && value.Length <= MaxPayloadBase64Length &&
               value == value.Trim();
    }

    // Routing hints are opaque identifiers chosen by this app (GUID "N").
    private static bool IsSafeToken(string s)
    {
        if (s.Length is < 1 or > 128) return false;
        foreach (var c in s)
        {
            if (!(c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '_' or '-'))
            {
                return false;
            }
        }
        return true;
    }

    private static bool IsStrictBase64(string s)
    {
        if (s.Length % 4 != 0) return false;
        var padding = 0;
        for (var i = 0; i < s.Length; i++)
        {
            var c = s[i];
            if (c == '=')
            {
                padding++;
                if (padding > 2 || i < s.Length - 2) return false;
            }
            else
            {
                if (padding > 0) return false;
                if (!(c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '+' or '/'))
                {
                    return false;
                }
            }
        }
        return true;
    }
}
