namespace OCS.Core.Models;

// Typed results of the audited cryptographic boundary (Rust bridge over the
// official Signal Protocol implementation). All byte[] values are opaque
// serialized records or ciphertext; nothing here is a homemade algorithm.

public sealed record IdentityCreation(
    byte[] IdentityKeyPair,
    byte[] IdentityPublicKey,
    uint RegistrationId,
    string Fingerprint);

public sealed record BundleCreationRequest(
    byte[] IdentityKeyPair,
    uint RegistrationId,
    uint DeviceId,
    uint SignedPreKeyId,
    uint KyberPreKeyId,
    uint OneTimePreKeyStartId,
    int OneTimePreKeyCount,
    int ValidityDays);

public sealed record PreKeyEntry(uint Id, byte[] Record);

public sealed record PrivateBundleMaterial(
    byte[] SignedPreKeyRecord,
    byte[] KyberPreKeyRecord,
    IReadOnlyList<PreKeyEntry> OneTimePreKeys);

public sealed record BundleCreation(string BundleJson, PrivateBundleMaterial Private);

public sealed record BundleValidation(
    string Fingerprint,
    uint RegistrationId,
    uint DeviceId,
    int OneTimePreKeyCount,
    DateTimeOffset ExpiresAtUtc);

public sealed record SessionInitRequest(
    byte[] IdentityKeyPair,
    uint RegistrationId,
    string LocalName,
    uint LocalDeviceId,
    string RemoteName,
    uint RemoteDeviceId,
    byte[] RemoteIdentityPublicKey,
    string BundleJson);

public sealed record SessionInitiation(byte[] SessionRecord, uint? SelectedOneTimePreKeyId);

public sealed record EncryptRequest(
    byte[] IdentityKeyPair,
    uint RegistrationId,
    string LocalName,
    uint LocalDeviceId,
    string RemoteName,
    uint RemoteDeviceId,
    byte[] RemoteIdentityPublicKey,
    byte[] SessionRecord,
    byte[] Plaintext);

public sealed record EncryptOutcome(byte[] SessionRecord, byte[] Ciphertext, int MessageType);

public sealed record DecryptRequest(
    byte[] IdentityKeyPair,
    uint RegistrationId,
    string LocalName,
    uint LocalDeviceId,
    string RemoteName,
    uint RemoteDeviceId,
    byte[] RemoteIdentityPublicKey,
    byte[]? SessionRecord,
    byte[] Ciphertext,
    int MessageType,
    IReadOnlyList<PreKeyEntry> SignedPreKeys,
    IReadOnlyList<PreKeyEntry> KyberPreKeys,
    IReadOnlyList<PreKeyEntry> OneTimePreKeys);

public sealed record DecryptOutcome(
    byte[] Plaintext,
    byte[] SessionRecord,
    uint? ConsumedOneTimePreKeyId,
    uint? ConsumedKyberPreKeyId);

public sealed record KdfRequest(
    string Password,
    byte[] Salt,
    int MemoryKiB = 65536,
    int Iterations = 3,
    int Parallelism = 4,
    int OutputLen = 32);

public sealed class CryptoException : Exception
{
    public string ErrorCode { get; }
    public CryptoException(string errorCode, string message) : base(message) => ErrorCode = errorCode;
}
