using System.Text.Json;
using System.Text.Json.Serialization;
using OCS.Core.Abstractions;
using OCS.Core.Models;

namespace OCS.Services.Storage;

// Master-password vault. Argon2id derives a key-encryption key (KEK) from the
// password + a unique random salt; the random database key and the random
// application-layer data key (DEK) are wrapped with XChaCha20Poly1305.
// The password itself is never stored. Wrong password => fail closed.
public sealed class VaultService
{
    public const int MinPasswordLength = 8;
    private const string VerifierPlaintext = "OCS vault verifier v1";
    private static readonly byte[] AadDbKey = "ocs-vault-v1:dbkey"u8.ToArray();
    private static readonly byte[] AadDek = "ocs-vault-v1:dek"u8.ToArray();
    private static readonly byte[] AadVerifier = "ocs-vault-v1:verifier"u8.ToArray();

    private readonly ICryptoEngine _crypto;
    private readonly string _vaultDirectory;

    public VaultService(ICryptoEngine crypto, string vaultDirectory)
    {
        _crypto = crypto;
        _vaultDirectory = vaultDirectory;
    }

    public string MetaPath => Path.Combine(_vaultDirectory, "vault.meta");
    public string DatabasePath => Path.Combine(_vaultDirectory, "ocs.db");
    public bool Exists => File.Exists(MetaPath);

    public sealed record KdfParams(
        [property: JsonPropertyName("algorithm")] string Algorithm,
        [property: JsonPropertyName("memoryKiB")] int MemoryKiB,
        [property: JsonPropertyName("iterations")] int Iterations,
        [property: JsonPropertyName("parallelism")] int Parallelism);

    public sealed record VaultMeta(
        [property: JsonPropertyName("format")] string Format,
        [property: JsonPropertyName("version")] int Version,
        [property: JsonPropertyName("kdf")] KdfParams Kdf,
        [property: JsonPropertyName("salt")] string Salt,
        [property: JsonPropertyName("wrappedDbKey")] string WrappedDbKey,
        [property: JsonPropertyName("wrappedDek")] string WrappedDek,
        [property: JsonPropertyName("verifier")] string Verifier,
        [property: JsonPropertyName("createdAtUtc")] string CreatedAtUtc);

    public sealed record VaultKeys(byte[] DbKey, byte[] Dek);

    public static KdfParams DefaultKdf => new("argon2id", 65536, 3, 4);

    public async Task<VaultKeys> CreateAsync(string password, CancellationToken ct)
    {
        ValidatePassword(password);
        if (Exists)
        {
            throw new CryptoException("vault_exists", "A vault already exists in this directory.");
        }
        Directory.CreateDirectory(_vaultDirectory);

        var salt = await _crypto.RandomBytesAsync(16, ct);
        var kek = await _crypto.DeriveKeyAsync(new KdfRequest(password, salt), ct);
        try
        {
            var dbKey = await _crypto.RandomBytesAsync(32, ct);
            var dek = await _crypto.RandomBytesAsync(32, ct);
            var meta = new VaultMeta(
                "ocs-vault", 1, DefaultKdf,
                Convert.ToBase64String(salt),
                Convert.ToBase64String(await _crypto.SealAsync(kek, dbKey, AadDbKey, ct)),
                Convert.ToBase64String(await _crypto.SealAsync(kek, dek, AadDek, ct)),
                Convert.ToBase64String(await _crypto.SealAsync(kek,
                    System.Text.Encoding.UTF8.GetBytes(VerifierPlaintext), AadVerifier, ct)),
                DateTimeOffset.UtcNow.ToString("O"));
            var json = JsonSerializer.Serialize(meta, new JsonSerializerOptions { WriteIndented = true });
            // Write atomically: temp file + move, so a crash never leaves a
            // half-written vault metadata file.
            var tmp = MetaPath + ".tmp";
            await File.WriteAllTextAsync(tmp, json, ct);
            File.Move(tmp, MetaPath, overwrite: false);
            return new VaultKeys(dbKey, dek);
        }
        finally
        {
            Array.Clear(kek);
        }
    }

    public async Task<VaultKeys> OpenAsync(string password, CancellationToken ct)
    {
        if (!Exists)
        {
            throw new CryptoException("vault_missing", "No vault exists in this directory.");
        }
        return await UnwrapAsync(ReadMeta(), password, ct);
    }

    // Used by backup restore: unwrap keys from a vault metadata JSON payload
    // carried inside an authenticated backup archive.
    public async Task<VaultKeys> OpenWithMetaJsonAsync(string metaJson, string password, CancellationToken ct)
    {
        var meta = JsonSerializer.Deserialize<VaultMeta>(metaJson)
            ?? throw new CryptoException("vault_corrupt", "Vault metadata is unreadable.");
        if (meta.Format != "ocs-vault" || meta.Version != 1 || meta.Kdf.Algorithm != "argon2id")
        {
            throw new CryptoException("vault_unsupported", "Unsupported vault format or KDF.");
        }
        return await UnwrapAsync(meta, password, ct);
    }

    private async Task<VaultKeys> UnwrapAsync(VaultMeta meta, string password, CancellationToken ct)
    {
        var salt = Convert.FromBase64String(meta.Salt);
        var kek = await _crypto.DeriveKeyAsync(new KdfRequest(password, salt,
            meta.Kdf.MemoryKiB, meta.Kdf.Iterations, meta.Kdf.Parallelism), ct);
        try
        {
            byte[] verifier;
            try
            {
                verifier = await _crypto.OpenAsync(kek,
                    Convert.FromBase64String(meta.Verifier), AadVerifier, ct);
            }
            catch (CryptoException)
            {
                throw new CryptoException("wrong_password",
                    "Wrong master password (or corrupted vault metadata). Refusing to open.");
            }
            if (!verifier.AsSpan().SequenceEqual(System.Text.Encoding.UTF8.GetBytes(VerifierPlaintext)))
            {
                throw new CryptoException("wrong_password", "Vault verifier mismatch. Refusing to open.");
            }
            var dbKey = await _crypto.OpenAsync(kek, Convert.FromBase64String(meta.WrappedDbKey), AadDbKey, ct);
            var dek = await _crypto.OpenAsync(kek, Convert.FromBase64String(meta.WrappedDek), AadDek, ct);
            return new VaultKeys(dbKey, dek);
        }
        finally
        {
            Array.Clear(kek);
        }
    }

    public VaultMeta ReadMeta()
    {
        var meta = JsonSerializer.Deserialize<VaultMeta>(File.ReadAllText(MetaPath))
            ?? throw new CryptoException("vault_corrupt", "Vault metadata is unreadable.");
        if (meta.Format != "ocs-vault" || meta.Version != 1 || meta.Kdf.Algorithm != "argon2id")
        {
            throw new CryptoException("vault_unsupported", "Unsupported vault format or KDF.");
        }
        return meta;
    }

    public static void ValidatePassword(string password)
    {
        if (password.Length < MinPasswordLength)
        {
            throw new CryptoException("weak_password",
                $"Master password must be at least {MinPasswordLength} characters.");
        }
        if (password.Length > 4096)
        {
            throw new CryptoException("weak_password", "Master password is too long.");
        }
    }
}
