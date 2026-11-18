using System.Text.Json;
using OCS.Core.Abstractions;
using OCS.Core.Models;

namespace OCS.Services.Crypto;

// ICryptoEngine over the Rust bridge. Stateless: protocol state enters and
// leaves as opaque serialized records so the repository can commit it in the
// same transaction as the message. No cryptography is implemented here.
public sealed class RustCryptoEngine : ICryptoEngine
{
    public RustCryptoEngine() => NativeBridge.EnsureReady();

    public async Task<IdentityCreation> CreateIdentityAsync(CancellationToken ct)
    {
        using var r = await NativeBridge.CallAsync("identity.generate", new { }, ct);
        var root = r.RootElement;
        return new IdentityCreation(
            B64(root, "identityKeyPair"),
            B64(root, "identityPublicKey"),
            root.GetProperty("registrationId").GetUInt32(),
            root.GetProperty("fingerprint").GetString()!);
    }

    public async Task<BundleCreation> CreateBundleAsync(BundleCreationRequest request, CancellationToken ct)
    {
        using var r = await NativeBridge.CallAsync("bundle.create", new
        {
            identityKeyPair = Convert.ToBase64String(request.IdentityKeyPair),
            registrationId = request.RegistrationId,
            deviceId = request.DeviceId,
            signedPreKeyId = request.SignedPreKeyId,
            kyberPreKeyId = request.KyberPreKeyId,
            oneTimePreKeyStartId = request.OneTimePreKeyStartId,
            oneTimePreKeyCount = request.OneTimePreKeyCount,
            validityDays = request.ValidityDays,
        }, ct);
        var root = r.RootElement;
        var bundleJson = root.GetProperty("bundle").GetRawText();
        var priv = root.GetProperty("private");
        var otpks = new List<PreKeyEntry>();
        foreach (var item in priv.GetProperty("oneTimePreKeys").EnumerateArray())
        {
            otpks.Add(new PreKeyEntry(item.GetProperty("id").GetUInt32(), B64(item, "record")));
        }
        return new BundleCreation(bundleJson, new PrivateBundleMaterial(
            B64(priv, "signedPreKeyRecord"),
            B64(priv, "kyberPreKeyRecord"),
            otpks));
    }

    public async Task<BundleValidation> ValidateBundleAsync(string bundleJson, CancellationToken ct)
    {
        using var bundleDoc = JsonDocument.Parse(bundleJson);
        using var r = await NativeBridge.CallAsync("bundle.validate",
            new { bundle = bundleDoc.RootElement }, ct);
        var root = r.RootElement;
        return new BundleValidation(
            root.GetProperty("fingerprint").GetString()!,
            root.GetProperty("registrationId").GetUInt32(),
            root.GetProperty("deviceId").GetUInt32(),
            root.GetProperty("oneTimePreKeyCount").GetInt32(),
            DateTimeOffset.Parse(root.GetProperty("expiresAtUtc").GetString()!,
                System.Globalization.CultureInfo.InvariantCulture));
    }

    public async Task<SessionInitiation> InitiateSessionAsync(SessionInitRequest request, CancellationToken ct)
    {
        using var bundleDoc = JsonDocument.Parse(request.BundleJson);
        using var r = await NativeBridge.CallAsync("session.init", new
        {
            identityKeyPair = Convert.ToBase64String(request.IdentityKeyPair),
            registrationId = request.RegistrationId,
            localName = request.LocalName,
            localDeviceId = request.LocalDeviceId,
            remoteName = request.RemoteName,
            remoteDeviceId = request.RemoteDeviceId,
            remoteIdentityPublicKey = Convert.ToBase64String(request.RemoteIdentityPublicKey),
            bundle = bundleDoc.RootElement,
        }, ct);
        var root = r.RootElement;
        uint? selected = root.TryGetProperty("selectedOneTimePreKeyId", out var sel)
            && sel.ValueKind != JsonValueKind.Null ? sel.GetUInt32() : null;
        return new SessionInitiation(B64(root, "sessionRecord"), selected);
    }

    public async Task<EncryptOutcome> EncryptAsync(EncryptRequest request, CancellationToken ct)
    {
        using var r = await NativeBridge.CallAsync("encrypt", new
        {
            identityKeyPair = Convert.ToBase64String(request.IdentityKeyPair),
            registrationId = request.RegistrationId,
            localName = request.LocalName,
            localDeviceId = request.LocalDeviceId,
            remoteName = request.RemoteName,
            remoteDeviceId = request.RemoteDeviceId,
            remoteIdentityPublicKey = Convert.ToBase64String(request.RemoteIdentityPublicKey),
            sessionRecord = Convert.ToBase64String(request.SessionRecord),
            plaintext = Convert.ToBase64String(request.Plaintext),
        }, ct);
        var root = r.RootElement;
        return new EncryptOutcome(
            B64(root, "sessionRecord"),
            B64(root, "ciphertext"),
            root.GetProperty("messageType").GetInt32());
    }

    public async Task<DecryptOutcome> DecryptAsync(DecryptRequest request, CancellationToken ct)
    {
        using var r = await NativeBridge.CallAsync("decrypt", new
        {
            identityKeyPair = Convert.ToBase64String(request.IdentityKeyPair),
            registrationId = request.RegistrationId,
            localName = request.LocalName,
            localDeviceId = request.LocalDeviceId,
            remoteName = request.RemoteName,
            remoteDeviceId = request.RemoteDeviceId,
            remoteIdentityPublicKey = Convert.ToBase64String(request.RemoteIdentityPublicKey),
            sessionRecord = request.SessionRecord is null ? null : Convert.ToBase64String(request.SessionRecord),
            ciphertext = Convert.ToBase64String(request.Ciphertext),
            messageType = request.MessageType,
            signedPreKeys = Entries(request.SignedPreKeys),
            kyberPreKeys = Entries(request.KyberPreKeys),
            oneTimePreKeys = Entries(request.OneTimePreKeys),
        }, ct);
        var root = r.RootElement;
        return new DecryptOutcome(
            B64(root, "plaintext"),
            B64(root, "sessionRecord"),
            NullableU32(root, "consumedOneTimePreKeyId"),
            NullableU32(root, "consumedKyberPreKeyId"));
    }

    public async Task<byte[]> DeriveKeyAsync(KdfRequest request, CancellationToken ct)
    {
        using var r = await NativeBridge.CallAsync("kdf.argon2id", new
        {
            password = request.Password,
            salt = Convert.ToBase64String(request.Salt),
            memoryKiB = request.MemoryKiB,
            iterations = request.Iterations,
            parallelism = request.Parallelism,
            outputLen = request.OutputLen,
        }, ct);
        return B64(r.RootElement, "key");
    }

    public async Task<byte[]> SealAsync(byte[] key, byte[] plaintext, byte[]? aad, CancellationToken ct)
    {
        using var r = await NativeBridge.CallAsync("aead.seal", new
        {
            key = Convert.ToBase64String(key),
            plaintext = Convert.ToBase64String(plaintext),
            aad = aad is null ? null : Convert.ToBase64String(aad),
        }, ct);
        return B64(r.RootElement, "sealed");
    }

    public async Task<byte[]> OpenAsync(byte[] key, byte[] sealedBytes, byte[]? aad, CancellationToken ct)
    {
        using var r = await NativeBridge.CallAsync("aead.open", new
        {
            key = Convert.ToBase64String(key),
            @sealed = Convert.ToBase64String(sealedBytes),
            aad = aad is null ? null : Convert.ToBase64String(aad),
        }, ct);
        return B64(r.RootElement, "plaintext");
    }

    public async Task<byte[]> RandomBytesAsync(int length, CancellationToken ct)
    {
        using var r = await NativeBridge.CallAsync("random", new { length }, ct);
        return B64(r.RootElement, "bytes");
    }

    public async Task<string> FingerprintAsync(byte[] identityPublicKey, CancellationToken ct)
    {
        using var r = await NativeBridge.CallAsync("fingerprint",
            new { identityPublicKey = Convert.ToBase64String(identityPublicKey) }, ct);
        return r.RootElement.GetProperty("fingerprint").GetString()!;
    }

    private static object[] Entries(IReadOnlyList<PreKeyEntry> entries)
    {
        var result = new object[entries.Count];
        for (var i = 0; i < entries.Count; i++)
        {
            result[i] = new { id = entries[i].Id, record = Convert.ToBase64String(entries[i].Record) };
        }
        return result;
    }

    private static byte[] B64(JsonElement obj, string name) =>
        Convert.FromBase64String(obj.GetProperty(name).GetString()!);

    private static uint? NullableU32(JsonElement obj, string name) =>
        obj.TryGetProperty(name, out var v) && v.ValueKind != JsonValueKind.Null
            ? v.GetUInt32() : null;
}
