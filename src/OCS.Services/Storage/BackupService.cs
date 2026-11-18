using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using OCS.Core.Abstractions;
using OCS.Core.Models;

namespace OCS.Services.Storage;

// Authenticated encrypted backups (STORAGE.md):
//   outer = { format, version, kdf, salt, sealed }
//   sealed = XChaCha20Poly1305( KEK_backup, innerJson, AAD "ocs-backup-v1" )
//   KEK_backup = Argon2id(master password, fresh random salt)
//   innerJson = { vaultMeta, database (SQLCipher snapshot), schemaVersion,
//                 cryptoImplementation, createdAtUtc }
// Restore validates EVERYTHING in a temporary location (outer AEAD, vault
// unwrap, SQLCipher integrity_check, schema version) and only then replaces
// the live files atomically. A corrupted or wrong-password backup never
// touches the active database. The backup password must be the vault's
// master password (the inner vaultMeta is wrapped under it).
public sealed class BackupService
{
    private static readonly byte[] BackupAad = "ocs-backup-v1"u8.ToArray();
    private const string CryptoImplementation = "ocs-signal-bridge v2 / libsignal 0.108.0 (PQXDH)";
    private static int _batteriesInitialized;

    private readonly ICryptoEngine _crypto;
    private readonly VaultService _vault;
    private readonly IEncryptedRepository? _repo;

    // repo may be null for restore-only usage (no live repository exists yet).
    public BackupService(ICryptoEngine crypto, VaultService vault, IEncryptedRepository? repo)
    {
        _crypto = crypto;
        _vault = vault;
        _repo = repo;
    }

    public async Task CreateAsync(string password, string outputPath, CancellationToken ct)
    {
        if (_repo is null)
        {
            throw new CryptoException("vault_missing", "Backup creation requires a live repository.");
        }
        VaultService.ValidatePassword(password);
        if (!_vault.Exists)
        {
            throw new CryptoException("vault_missing", "No vault exists to back up.");
        }
        var metaJson = await File.ReadAllTextAsync(_vault.MetaPath, ct);
        var snapshot = await _repo.CreateSnapshotAsync(ct);
        var salt = await _crypto.RandomBytesAsync(16, ct);
        var kek = await _crypto.DeriveKeyAsync(new KdfRequest(password, salt), ct);
        try
        {
            var inner = JsonSerializer.Serialize(new
            {
                vaultMeta = metaJson,
                database = Convert.ToBase64String(snapshot),
                schemaVersion = 1,
                cryptoImplementation = CryptoImplementation,
                createdAtUtc = DateTimeOffset.UtcNow.ToString("O"),
            });
            var sealedBytes = await _crypto.SealAsync(kek, Encoding.UTF8.GetBytes(inner), BackupAad, ct);
            var outer = JsonSerializer.Serialize(new
            {
                format = "ocs-backup",
                version = 1,
                kdf = new
                {
                    algorithm = "argon2id",
                    memoryKiB = VaultService.DefaultKdf.MemoryKiB,
                    iterations = VaultService.DefaultKdf.Iterations,
                    parallelism = VaultService.DefaultKdf.Parallelism,
                },
                salt = Convert.ToBase64String(salt),
                @sealed = Convert.ToBase64String(sealedBytes),
                createdAtUtc = DateTimeOffset.UtcNow.ToString("O"),
            }, new JsonSerializerOptions { WriteIndented = true });

            var tmp = outputPath + ".tmp";
            await File.WriteAllTextAsync(tmp, outer, ct);
            File.Move(tmp, outputPath, overwrite: true);
        }
        finally
        {
            Array.Clear(kek);
            Array.Clear(snapshot);
        }
    }

    // The caller MUST dispose the live repository before restoring (the active
    // SQLCipher connection holds file locks). After restore, re-open the vault.
    public async Task RestoreAsync(string backupPath, string password, CancellationToken ct)
    {
        VaultService.ValidatePassword(password);
        string outerJson;
        try
        {
            outerJson = await File.ReadAllTextAsync(backupPath, ct);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new CryptoException("backup_unreadable", "Backup file cannot be read.");
        }

        // Any structural damage (bad JSON, bad base64, missing fields, absurd
        // KDF parameters) must fail closed as backup_corrupt — never leak a
        // raw FormatException/JsonException to the caller.
        byte[] salt;
        byte[] sealedBytes;
        int memoryKiB, iterations, parallelism;
        try
        {
            using var outer = JsonDocument.Parse(outerJson);
            var root = outer.RootElement;
            if (root.GetProperty("format").GetString() != "ocs-backup" ||
                root.GetProperty("version").GetInt32() != 1)
            {
                throw new CryptoException("backup_unsupported", "Unsupported backup format or version.");
            }
            var kdf = root.GetProperty("kdf");
            if (kdf.GetProperty("algorithm").GetString() != "argon2id")
            {
                throw new CryptoException("backup_unsupported", "Unsupported backup KDF.");
            }
            salt = Convert.FromBase64String(root.GetProperty("salt").GetString()!);
            sealedBytes = Convert.FromBase64String(root.GetProperty("sealed").GetString()!);
            memoryKiB = kdf.GetProperty("memoryKiB").GetInt32();
            iterations = kdf.GetProperty("iterations").GetInt32();
            parallelism = kdf.GetProperty("parallelism").GetInt32();
        }
        catch (Exception e) when (e is JsonException or FormatException or InvalidOperationException
            or KeyNotFoundException or ArgumentOutOfRangeException or OverflowException)
        {
            throw new CryptoException("backup_corrupt",
                "Backup file is malformed. Active database untouched.");
        }

        byte[] kek;
        try
        {
            kek = await _crypto.DeriveKeyAsync(new KdfRequest(password, salt,
                memoryKiB, iterations, parallelism), ct);
        }
        catch (CryptoException)
        {
            throw new CryptoException("backup_corrupt",
                "Backup KDF parameters are invalid. Active database untouched.");
        }
        string innerJson;
        try
        {
            innerJson = Encoding.UTF8.GetString(
                await _crypto.OpenAsync(kek, sealedBytes, BackupAad, ct));
        }
        catch (CryptoException)
        {
            throw new CryptoException("backup_corrupt",
                "Backup failed authentication (wrong password or corrupted file). Active database untouched.");
        }
        finally
        {
            Array.Clear(kek);
        }

        string metaJson;
        byte[] dbBytes;
        try
        {
            using var inner = JsonDocument.Parse(innerJson);
            var ir = inner.RootElement;
            if (ir.GetProperty("schemaVersion").GetInt32() != 1)
            {
                throw new CryptoException("backup_unsupported", "Unsupported backup schema version.");
            }
            metaJson = ir.GetProperty("vaultMeta").GetString()!;
            dbBytes = Convert.FromBase64String(ir.GetProperty("database").GetString()!);
        }
        catch (Exception e) when (e is JsonException or FormatException or InvalidOperationException
            or KeyNotFoundException or ArgumentOutOfRangeException or OverflowException)
        {
            throw new CryptoException("backup_corrupt",
                "Backup payload is malformed. Active database untouched.");
        }

        // Unwrapping with the same password proves the backup belongs to this
        // vault's master password; wrong password fails closed here.
        var keys = await _vault.OpenWithMetaJsonAsync(metaJson, password, ct);
        try
        {
            var tmpDb = _vault.DatabasePath + ".restore-tmp";
            Directory.CreateDirectory(Path.GetDirectoryName(tmpDb)!);
            await File.WriteAllBytesAsync(tmpDb, dbBytes, ct);
            try
            {
                ValidateSnapshot(tmpDb, keys.DbKey);
            }
            catch
            {
                File.Delete(tmpDb);
                throw;
            }

            // Atomic replacement. Old WAL/SHM sidecars belong to the previous
            // database and must not survive the swap.
            File.Move(tmpDb, _vault.DatabasePath, overwrite: true);
            TryDelete(_vault.DatabasePath + "-wal");
            TryDelete(_vault.DatabasePath + "-shm");
            TryDelete(_vault.DatabasePath + "-journal");

            var tmpMeta = _vault.MetaPath + ".tmp";
            await File.WriteAllTextAsync(tmpMeta, metaJson, ct);
            File.Move(tmpMeta, _vault.MetaPath, overwrite: true);
        }
        finally
        {
            Array.Clear(keys.DbKey);
            Array.Clear(keys.Dek);
            Array.Clear(dbBytes);
        }
    }

    private static void ValidateSnapshot(string path, byte[] dbKey)
    {
        if (Interlocked.Exchange(ref _batteriesInitialized, 1) == 0)
        {
            SQLitePCL.Batteries_V2.Init();
        }
        var csb = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWrite,
            Pooling = false,
        };
        using var conn = new SqliteConnection(csb.ToString());
        conn.Open();
        using (var key = conn.CreateCommand())
        {
            key.CommandText = $"PRAGMA key = \"x'{Convert.ToHexString(dbKey)}'\"";
            key.ExecuteNonQuery();
        }
        using (var probe = conn.CreateCommand())
        {
            probe.CommandText = "SELECT count(*) FROM sqlite_master";
            probe.ExecuteScalar(); // throws if the key is wrong
        }
        using (var integrity = conn.CreateCommand())
        {
            integrity.CommandText = "PRAGMA integrity_check";
            var result = integrity.ExecuteScalar() as string;
            if (result != "ok")
            {
                throw new CryptoException("backup_corrupt", "Backup database failed integrity_check.");
            }
        }
        using (var schema = conn.CreateCommand())
        {
            schema.CommandText = "SELECT version FROM schema_info LIMIT 1";
            var version = schema.ExecuteScalar();
            if (version is null || Convert.ToInt32(version) != 1)
            {
                throw new CryptoException("backup_unsupported", "Backup database schema version mismatch.");
            }
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path)) File.Delete(path);
        }
        catch (IOException)
        {
            // sidecar may be locked by another process; the fresh connection
            // will recreate/recover it. Never fail the restore for this.
        }
    }
}
