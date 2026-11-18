using OCS.Core.Models;

namespace OCS.Core.Abstractions;

// The cryptographic boundary. Implementations delegate to an audited protocol
// implementation (official Signal Protocol stack via the Rust bridge); they
// never invent algorithms. The engine is stateless: durable protocol state is
// passed in and returned so the repository can persist it transactionally.
public interface ICryptoEngine
{
    Task<IdentityCreation> CreateIdentityAsync(CancellationToken ct);
    Task<BundleCreation> CreateBundleAsync(BundleCreationRequest request, CancellationToken ct);
    Task<BundleValidation> ValidateBundleAsync(string bundleJson, CancellationToken ct);
    Task<SessionInitiation> InitiateSessionAsync(SessionInitRequest request, CancellationToken ct);
    Task<EncryptOutcome> EncryptAsync(EncryptRequest request, CancellationToken ct);
    Task<DecryptOutcome> DecryptAsync(DecryptRequest request, CancellationToken ct);
    Task<byte[]> DeriveKeyAsync(KdfRequest request, CancellationToken ct);
    Task<byte[]> SealAsync(byte[] key, byte[] plaintext, byte[]? aad, CancellationToken ct);
    Task<byte[]> OpenAsync(byte[] key, byte[] sealedBytes, byte[]? aad, CancellationToken ct);
    Task<byte[]> RandomBytesAsync(int length, CancellationToken ct);
    Task<string> FingerprintAsync(byte[] identityPublicKey, CancellationToken ct);
}
