using System.Text;
using OCS.Core.Abstractions;
using OCS.Core.Models;
using OCS.Services.Crypto;
using Xunit;

namespace OCS.Tests;

// Primitive-level checks against the Rust bridge (official libsignal stack).
// Small Argon2id parameters are used HERE ONLY for unit-test speed; the vault
// always uses the calibrated production parameters (64 MiB / t=3 / p=4).
public class BridgeAndPrimitiveTests
{
    private readonly RustCryptoEngine _crypto = new();
    private readonly CancellationToken _ct = CancellationToken.None;

    [Fact]
    public async Task RandomBytes_AreRequestedLengthAndUnpredictable()
    {
        var a = await _crypto.RandomBytesAsync(32, _ct);
        var b = await _crypto.RandomBytesAsync(32, _ct);
        Assert.Equal(32, a.Length);
        Assert.NotEqual(a, b);
    }

    [Fact]
    public async Task Kdf_IsDeterministic_SaltSensitive_PasswordSensitive()
    {
        var salt1 = await _crypto.RandomBytesAsync(16, _ct);
        var salt2 = await _crypto.RandomBytesAsync(16, _ct);
        var req = new KdfRequest("correct horse battery staple", salt1, 8, 1, 1, 32);
        var k1 = await _crypto.DeriveKeyAsync(req, _ct);
        var k2 = await _crypto.DeriveKeyAsync(req, _ct);
        Assert.Equal(k1, k2);
        Assert.Equal(32, k1.Length);

        var otherSalt = await _crypto.DeriveKeyAsync(req with { Salt = salt2 }, _ct);
        Assert.NotEqual(k1, otherSalt);

        var wrongPw = await _crypto.DeriveKeyAsync(req with { Password = "wrong password" }, _ct);
        Assert.NotEqual(k1, wrongPw);
    }

    [Fact]
    public async Task Aead_RoundTrip_Tamper_WrongKey_WrongAad_AllFailClosed()
    {
        var key = await _crypto.RandomBytesAsync(32, _ct);
        var wrongKey = await _crypto.RandomBytesAsync(32, _ct);
        var plaintext = Encoding.UTF8.GetBytes("敏感内容 secret payload");
        var aad = Encoding.UTF8.GetBytes("ocs-test-aad");

        var sealedBytes = await _crypto.SealAsync(key, plaintext, aad, _ct);
        var opened = await _crypto.OpenAsync(key, sealedBytes, aad, _ct);
        Assert.Equal(plaintext, opened);

        var tampered = (byte[])sealedBytes.Clone();
        tampered[^1] ^= 0xFF;
        await Assert.ThrowsAsync<CryptoException>(() => _crypto.OpenAsync(key, tampered, aad, _ct));
        await Assert.ThrowsAsync<CryptoException>(() => _crypto.OpenAsync(wrongKey, sealedBytes, aad, _ct));
        await Assert.ThrowsAsync<CryptoException>(
            () => _crypto.OpenAsync(key, sealedBytes, Encoding.UTF8.GetBytes("other-aad"), _ct));
    }

    [Fact]
    public async Task Identity_FingerprintIsStableAndFormatted()
    {
        var id = await _crypto.CreateIdentityAsync(_ct);
        Assert.NotEmpty(id.IdentityKeyPair);
        Assert.NotEmpty(id.IdentityPublicKey);
        Assert.InRange(id.RegistrationId, 1u, 16383u);

        var fp = await _crypto.FingerprintAsync(id.IdentityPublicKey, _ct);
        Assert.Equal(id.Fingerprint, fp);
        var groups = fp.Split(' ');
        Assert.Equal(8, groups.Length);
        Assert.All(groups, g => Assert.Equal(8, g.Length));

        var id2 = await _crypto.CreateIdentityAsync(_ct);
        Assert.NotEqual(id.Fingerprint, id2.Fingerprint);
    }
}
