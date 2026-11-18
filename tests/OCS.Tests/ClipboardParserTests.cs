using OCS.Services.Clipboard;
using Xunit;

namespace OCS.Tests;

// Strict envelope parser: oversized / malformed / hostile clipboard input must
// be ignored safely (TEST-PLAN: clipboard guards).
public class ClipboardParserTests
{
    private static byte[] TypedPayload(byte type = 3)
    {
        var payload = new byte[65];
        payload[0] = type;
        for (var i = 1; i < payload.Length; i++) payload[i] = (byte)(i * 7);
        return payload;
    }

    [Fact]
    public void BuildEnvelope_Parse_RoundTrips()
    {
        var text = CipherDetector.BuildEnvelope("conv-1", "msg-1", TypedPayload());
        Assert.True(CipherDetector.LooksLikeEnvelope(text));
        Assert.True(CipherDetector.TryParse(text, out var env));
        Assert.NotNull(env);
        Assert.Equal(1, env.Version);
        Assert.Equal("conv-1", env.ConversationHint);
        Assert.Equal("msg-1", env.MessageId);
        Assert.Equal(Convert.ToBase64String(TypedPayload()), env.PayloadBase64);
    }

    [Fact]
    public void OversizedText_IsRejected()
    {
        var huge = new string('A', CipherDetector.MaxTextLength + 1);
        Assert.False(CipherDetector.TryParse(huge, out _));
        var hugeEnvelope = CipherDetector.BuildEnvelope("c", "m", TypedPayload())
            + new string('B', CipherDetector.MaxTextLength);
        Assert.False(CipherDetector.TryParse(hugeEnvelope, out _));
    }

    [Theory]
    [InlineData("")]
    [InlineData("hello world, just plain text")]
    [InlineData("-----BEGIN OCS ENCRYPTED MESSAGE-----\nOCS-Version: 1\n-----END OCS ENCRYPTED MESSAGE-----")]
    public void PlainOrTruncatedText_IsRejected(string text)
    {
        Assert.False(CipherDetector.TryParse(text, out _));
    }

    [Fact]
    public void WrongVersion_IsRejected()
    {
        var text = CipherDetector.BuildEnvelope("c", "m", TypedPayload())
            .Replace("OCS-Version: 1", "OCS-Version: 2");
        Assert.False(CipherDetector.TryParse(text, out _));
    }

    [Fact]
    public void UnknownHeader_IsRejected()
    {
        var text = CipherDetector.BuildEnvelope("c", "m", TypedPayload())
            .Replace("OCS-Version: 1", "OCS-Version: 1\nX-Inject: whatever");
        Assert.False(CipherDetector.TryParse(text, out _));
    }

    [Fact]
    public void InvalidBase64_IsRejected()
    {
        var text = CipherDetector.BuildEnvelope("c", "m", TypedPayload());
        var lines = text.Split('\n');
        lines[4] = "Payload: !!!not-base64!!!";
        Assert.False(CipherDetector.TryParse(string.Join('\n', lines), out _));
    }

    [Fact]
    public void UnknownPayloadType_IsRejected()
    {
        var text = CipherDetector.BuildEnvelope("c", "m", TypedPayload(type: 9));
        Assert.False(CipherDetector.TryParse(text, out _));
    }

    [Fact]
    public void HostileConversationHint_IsRejected()
    {
        var text = CipherDetector.BuildEnvelope("c", "m", TypedPayload())
            .Replace("OCS-Conversation: c", "OCS-Conversation: ../../etc/passwd");
        Assert.False(CipherDetector.TryParse(text, out _));
    }

    [Fact]
    public void WrongLineOrder_IsRejected()
    {
        var text = CipherDetector.BuildEnvelope("c", "m", TypedPayload());
        var lines = text.Split('\n');
        (lines[1], lines[2]) = (lines[2], lines[1]);
        Assert.False(CipherDetector.TryParse(string.Join('\n', lines), out _));
    }
}
