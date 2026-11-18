using System.Globalization;
using System.Text;
using Microsoft.Data.Sqlite;
using OCS.Core.Abstractions;
using OCS.Core.Models;
using OCS.Services.Messaging;

namespace OCS.Services.Storage;

// SQLCipher-backed encrypted repository (ADR-004: fail closed, no plaintext
// fallback). Two layers: the whole database is encrypted by SQLCipher with a
// random raw key, and sensitive columns additionally use application-layer
// XChaCha20Poly1305 with per-row AAD binding. Message rows and updated protocol
// state commit in ONE transaction. A global gate serializes SQLite access.
public sealed class SqlCipherRepository : IEncryptedRepository, SqlCipherRepositoryAccess
{
    private const int SchemaVersion = 1;
    private static int _batteriesInitialized;

    private readonly ICryptoEngine _crypto;
    private readonly VaultService.VaultKeys _keys;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private SqliteConnection? _conn;
    private bool _disposed;

    public string DatabasePath { get; }

    // Narrow seam for in-memory decryption of security-event details (UI).
    byte[] SqlCipherRepositoryAccess.Dek => _keys.Dek;

    public SqlCipherRepository(ICryptoEngine crypto, string databasePath, VaultService.VaultKeys keys)
    {
        _crypto = crypto;
        DatabasePath = databasePath;
        _keys = keys;
    }

    private SqliteConnection Conn =>
        _conn ?? throw new InvalidOperationException("Repository is not initialized.");

    public async Task InitializeAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            if (Interlocked.CompareExchange(ref _batteriesInitialized, 1, 0) == 0)
            {
                SQLitePCL.Batteries_V2.Init();
            }
            Directory.CreateDirectory(Path.GetDirectoryName(DatabasePath)!);
            var csb = new SqliteConnectionStringBuilder
            {
                DataSource = DatabasePath,
                Pooling = false,
            };
            _conn = new SqliteConnection(csb.ToString());
            await _conn.OpenAsync(ct);

            // Raw 256-bit key (no KDF on the DB key itself; it is random and
            // wrapped by the password-derived KEK in vault.meta).
            await ExecAsync($"PRAGMA key = \"x'{Convert.ToHexString(_keys.DbKey)}'\"", ct);
            // Any read fails with "file is not a database" on a wrong key.
            await using (var probe = Conn.CreateCommand())
            {
                probe.CommandText = "SELECT count(*) FROM sqlite_master";
                await probe.ExecuteScalarAsync(ct);
            }
            await ExecAsync("PRAGMA foreign_keys=ON", ct);
            await ExecAsync("PRAGMA journal_mode=WAL", ct);

            var exists = await TableExistsAsync("schema_info", ct);
            if (!exists)
            {
                await CreateSchemaAsync(ct);
            }
            else
            {
                var version = await ScalarLongAsync("SELECT version FROM schema_info LIMIT 1", ct);
                if (version != SchemaVersion)
                {
                    throw new CryptoException("schema_unsupported",
                        $"Unsupported database schema version {version}.");
                }
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task CreateSchemaAsync(CancellationToken ct)
    {
        const string ddl = """
            CREATE TABLE schema_info(version INTEGER NOT NULL);
            CREATE TABLE contacts(
              id TEXT PRIMARY KEY,
              display_name_enc BLOB NOT NULL,
              identity_fingerprint TEXT NOT NULL,
              identity_public_key BLOB NOT NULL,
              trust_state TEXT NOT NULL,
              created_at TEXT NOT NULL);
            CREATE TABLE conversations(
              id TEXT PRIMARY KEY,
              contact_id TEXT NOT NULL REFERENCES contacts(id),
              display_name_enc BLOB NOT NULL,
              protocol_id TEXT NOT NULL,
              state_blob_enc BLOB,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL);
            CREATE TABLE messages(
              id TEXT PRIMARY KEY,
              conversation_id TEXT NOT NULL REFERENCES conversations(id),
              direction INTEGER NOT NULL,
              envelope_enc BLOB NOT NULL,
              plaintext_enc BLOB,
              created_at TEXT NOT NULL,
              local_status TEXT NOT NULL,
              envelope_hash TEXT NOT NULL UNIQUE);
            CREATE INDEX idx_messages_conv ON messages(conversation_id, created_at);
            CREATE TABLE identity_material(
              id INTEGER PRIMARY KEY CHECK (id = 1),
              kind TEXT NOT NULL,
              key_blob_enc BLOB NOT NULL,
              registration_id INTEGER NOT NULL,
              key_version INTEGER NOT NULL,
              created_at TEXT NOT NULL);
            CREATE TABLE prekey_material(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              key_id INTEGER NOT NULL,
              kind TEXT NOT NULL,
              key_blob_enc BLOB NOT NULL,
              consumed_at TEXT,
              key_version INTEGER NOT NULL,
              UNIQUE(kind, key_id));
            CREATE TABLE exchange_packages(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              peer_id TEXT NOT NULL,
              package_hash TEXT NOT NULL UNIQUE,
              package_version INTEGER NOT NULL,
              imported_at TEXT NOT NULL,
              status TEXT NOT NULL);
            CREATE TABLE security_events(
              id TEXT PRIMARY KEY,
              event_type TEXT NOT NULL,
              details_enc BLOB NOT NULL,
              created_at TEXT NOT NULL);
            CREATE TABLE app_settings(
              setting_key TEXT PRIMARY KEY,
              value_enc BLOB NOT NULL);
            """;
        await using var tx = (SqliteTransaction)await Conn.BeginTransactionAsync(ct);
        await using (var cmd = Conn.CreateCommand())
        {
            cmd.Transaction = tx;
            cmd.CommandText = ddl;
            await cmd.ExecuteNonQueryAsync(ct);
        }
        await using (var cmd = Conn.CreateCommand())
        {
            cmd.Transaction = tx;
            cmd.CommandText = "INSERT INTO schema_info(version) VALUES (@v)";
            cmd.Parameters.AddWithValue("@v", SchemaVersion);
            await cmd.ExecuteNonQueryAsync(ct);
        }
        await tx.CommitAsync(ct);
    }

    // ── contacts ─────────────────────────────────────────────────────────────

    public async Task<ContactRecord> AddContactAsync(string displayName, string identityFingerprint,
        byte[] identityPublicKey, CancellationToken ct)
    {
        var id = Guid.NewGuid().ToString("N");
        var now = DateTimeOffset.UtcNow;
        var nameEnc = await SealTextAsync(displayName, $"ocs-col-v1:contact-name:{id}", ct);
        await _gate.WaitAsync(ct);
        try
        {
            await using var cmd = Conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO contacts(id, display_name_enc, identity_fingerprint, identity_public_key, trust_state, created_at)
                VALUES (@id, @name, @fp, @pk, @trust, @created)
                """;
            cmd.Parameters.AddWithValue("@id", id);
            cmd.Parameters.AddWithValue("@name", nameEnc);
            cmd.Parameters.AddWithValue("@fp", identityFingerprint);
            cmd.Parameters.AddWithValue("@pk", identityPublicKey);
            cmd.Parameters.AddWithValue("@trust", TrustStates.Unverified);
            cmd.Parameters.AddWithValue("@created", now.ToString("O"));
            await cmd.ExecuteNonQueryAsync(ct);
        }
        finally { _gate.Release(); }
        return new ContactRecord(id, displayName, identityFingerprint, identityPublicKey,
            TrustStates.Unverified, now);
    }

    public async Task<IReadOnlyList<ContactRecord>> GetContactsAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            var rows = new List<(string Id, byte[] NameEnc, string Fp, byte[] Pk, string Trust, string Created)>();
            await using var cmd = Conn.CreateCommand();
            cmd.CommandText = "SELECT id, display_name_enc, identity_fingerprint, identity_public_key, trust_state, created_at FROM contacts ORDER BY created_at";
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                rows.Add((reader.GetString(0), (byte[])reader[1], reader.GetString(2),
                    (byte[])reader[3], reader.GetString(4), reader.GetString(5)));
            }
            var result = new List<ContactRecord>(rows.Count);
            foreach (var r in rows)
            {
                var name = await OpenTextAsync(r.NameEnc, $"ocs-col-v1:contact-name:{r.Id}", ct);
                result.Add(new ContactRecord(r.Id, name, r.Fp, r.Pk, r.Trust, ParseTime(r.Created)));
            }
            return result;
        }
        finally { _gate.Release(); }
    }

    public async Task<ContactRecord?> GetContactAsync(string contactId, CancellationToken ct)
    {
        var all = await GetContactsAsync(ct);
        return all.FirstOrDefault(c => c.Id == contactId);
    }

    public async Task SetContactTrustAsync(string contactId, string trustState, CancellationToken ct)
    {
        if (trustState != TrustStates.Unverified && trustState != TrustStates.Verified)
        {
            throw new ArgumentException("Invalid trust state.", nameof(trustState));
        }
        await _gate.WaitAsync(ct);
        try
        {
            await using var cmd = Conn.CreateCommand();
            cmd.CommandText = "UPDATE contacts SET trust_state=@trust WHERE id=@id";
            cmd.Parameters.AddWithValue("@trust", trustState);
            cmd.Parameters.AddWithValue("@id", contactId);
            await cmd.ExecuteNonQueryAsync(ct);
        }
        finally { _gate.Release(); }
    }

    public async Task SetContactDisplayNameAsync(string contactId, string displayName, CancellationToken ct)
    {
        var nameEnc = await SealTextAsync(displayName, $"ocs-col-v1:contact-name:{contactId}", ct);
        await _gate.WaitAsync(ct);
        try
        {
            await using var cmd = Conn.CreateCommand();
            cmd.CommandText = "UPDATE contacts SET display_name_enc=@name WHERE id=@id";
            cmd.Parameters.AddWithValue("@name", nameEnc);
            cmd.Parameters.AddWithValue("@id", contactId);
            await cmd.ExecuteNonQueryAsync(ct);
        }
        finally { _gate.Release(); }
    }

    // ── conversations ────────────────────────────────────────────────────────

    public async Task<ConversationRecord> CreateConversationAsync(string contactId, string displayName,
        string protocolId, CancellationToken ct)
    {
        var id = Guid.NewGuid().ToString("N");
        var now = DateTimeOffset.UtcNow;
        var nameEnc = await SealTextAsync(displayName, $"ocs-col-v1:conv-name:{id}", ct);
        await _gate.WaitAsync(ct);
        try
        {
            await using var cmd = Conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO conversations(id, contact_id, display_name_enc, protocol_id, state_blob_enc, created_at, updated_at)
                VALUES (@id, @contact, @name, @proto, NULL, @created, @updated)
                """;
            cmd.Parameters.AddWithValue("@id", id);
            cmd.Parameters.AddWithValue("@contact", contactId);
            cmd.Parameters.AddWithValue("@name", nameEnc);
            cmd.Parameters.AddWithValue("@proto", protocolId);
            cmd.Parameters.AddWithValue("@created", now.ToString("O"));
            cmd.Parameters.AddWithValue("@updated", now.ToString("O"));
            await cmd.ExecuteNonQueryAsync(ct);
        }
        finally { _gate.Release(); }
        return new ConversationRecord(id, contactId, displayName, protocolId, null, now, now);
    }

    public async Task<IReadOnlyList<ConversationRecord>> GetConversationsAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            var rows = new List<(string Id, string Contact, byte[] NameEnc, string Proto, byte[]? State, string Created, string Updated)>();
            await using var cmd = Conn.CreateCommand();
            cmd.CommandText = "SELECT id, contact_id, display_name_enc, protocol_id, state_blob_enc, created_at, updated_at FROM conversations ORDER BY updated_at DESC";
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                rows.Add((reader.GetString(0), reader.GetString(1), (byte[])reader[2],
                    reader.GetString(3), reader.IsDBNull(4) ? null : (byte[])reader[4],
                    reader.GetString(5), reader.GetString(6)));
            }
            var result = new List<ConversationRecord>(rows.Count);
            foreach (var r in rows)
            {
                var name = await OpenTextAsync(r.NameEnc, $"ocs-col-v1:conv-name:{r.Id}", ct);
                byte[]? state = null;
                if (r.State is not null)
                {
                    state = await _crypto.OpenAsync(_keys.Dek, r.State,
                        Encoding.UTF8.GetBytes($"ocs-col-v1:conv-state:{r.Id}"), ct);
                }
                result.Add(new ConversationRecord(r.Id, r.Contact, name, r.Proto, state,
                    ParseTime(r.Created), ParseTime(r.Updated)));
            }
            return result;
        }
        finally { _gate.Release(); }
    }

    public async Task<ConversationRecord?> GetConversationAsync(string conversationId, CancellationToken ct)
    {
        var all = await GetConversationsAsync(ct);
        return all.FirstOrDefault(c => c.Id == conversationId);
    }

    public async Task SaveConversationStateAsync(string conversationId, byte[] stateBlob, CancellationToken ct)
    {
        var enc = await _crypto.SealAsync(_keys.Dek, stateBlob,
            Encoding.UTF8.GetBytes($"ocs-col-v1:conv-state:{conversationId}"), ct);
        await _gate.WaitAsync(ct);
        try
        {
            await using var cmd = Conn.CreateCommand();
            cmd.CommandText = "UPDATE conversations SET state_blob_enc=@state, updated_at=@now WHERE id=@id";
            cmd.Parameters.AddWithValue("@state", enc);
            cmd.Parameters.AddWithValue("@now", DateTimeOffset.UtcNow.ToString("O"));
            cmd.Parameters.AddWithValue("@id", conversationId);
            await cmd.ExecuteNonQueryAsync(ct);
        }
        finally { _gate.Release(); }
    }

    // ── messages (atomic message + protocol state) ───────────────────────────

    public async Task SaveMessageWithStateAsync(StoredMessage message, byte[]? newStateBlob,
        uint? consumedOneTimePreKeyId, CancellationToken ct)
    {
        var envEnc = await _crypto.SealAsync(_keys.Dek, message.EncryptedPayload,
            Encoding.UTF8.GetBytes($"ocs-col-v1:msg-env:{message.MessageId}"), ct);
        byte[]? ptEnc = null;
        if (message.Plaintext is not null)
        {
            ptEnc = await _crypto.SealAsync(_keys.Dek, Encoding.UTF8.GetBytes(message.Plaintext),
                Encoding.UTF8.GetBytes($"ocs-col-v1:msg-pt:{message.MessageId}"), ct);
        }
        byte[]? stateEnc = null;
        if (newStateBlob is not null)
        {
            stateEnc = await _crypto.SealAsync(_keys.Dek, newStateBlob,
                Encoding.UTF8.GetBytes($"ocs-col-v1:conv-state:{message.ConversationId}"), ct);
        }

        await _gate.WaitAsync(ct);
        try
        {
            await using var tx = (SqliteTransaction)await Conn.BeginTransactionAsync(ct);
            await using (var cmd = Conn.CreateCommand())
            {
                cmd.Transaction = tx;
                cmd.CommandText = """
                    INSERT INTO messages(id, conversation_id, direction, envelope_enc, plaintext_enc, created_at, local_status, envelope_hash)
                    VALUES (@id, @conv, @dir, @env, @pt, @created, @status, @hash)
                    """;
                cmd.Parameters.AddWithValue("@id", message.MessageId);
                cmd.Parameters.AddWithValue("@conv", message.ConversationId);
                cmd.Parameters.AddWithValue("@dir", (int)message.Direction);
                cmd.Parameters.AddWithValue("@env", envEnc);
                cmd.Parameters.AddWithValue("@pt", (object?)ptEnc ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@created", message.CreatedAtUtc.ToString("O"));
                cmd.Parameters.AddWithValue("@status", message.LocalStatus);
                cmd.Parameters.AddWithValue("@hash", message.EnvelopeHash);
                await cmd.ExecuteNonQueryAsync(ct);
            }
            if (stateEnc is not null)
            {
                await using var cmd = Conn.CreateCommand();
                cmd.Transaction = tx;
                cmd.CommandText = "UPDATE conversations SET state_blob_enc=@state, updated_at=@now WHERE id=@id";
                cmd.Parameters.AddWithValue("@state", stateEnc);
                cmd.Parameters.AddWithValue("@now", DateTimeOffset.UtcNow.ToString("O"));
                cmd.Parameters.AddWithValue("@id", message.ConversationId);
                await cmd.ExecuteNonQueryAsync(ct);
            }
            if (consumedOneTimePreKeyId is { } consumed)
            {
                await using var cmd = Conn.CreateCommand();
                cmd.Transaction = tx;
                cmd.CommandText = "UPDATE prekey_material SET consumed_at=@now WHERE kind='otpk' AND key_id=@key AND consumed_at IS NULL";
                cmd.Parameters.AddWithValue("@now", DateTimeOffset.UtcNow.ToString("O"));
                cmd.Parameters.AddWithValue("@key", (long)consumed);
                await cmd.ExecuteNonQueryAsync(ct);
            }
            await tx.CommitAsync(ct);
        }
        finally { _gate.Release(); }
    }

    public async Task<IReadOnlyList<StoredMessage>> GetMessagesAsync(string conversationId, int limit,
        CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            var rows = new List<(string Id, string Conv, int Dir, byte[] EnvEnc, byte[]? PtEnc, string Created, string Status, string Hash)>();
            await using var cmd = Conn.CreateCommand();
            cmd.CommandText = """
                SELECT id, conversation_id, direction, envelope_enc, plaintext_enc, created_at, local_status, envelope_hash
                FROM messages WHERE conversation_id=@conv ORDER BY created_at DESC, rowid DESC LIMIT @limit
                """;
            cmd.Parameters.AddWithValue("@conv", conversationId);
            cmd.Parameters.AddWithValue("@limit", limit);
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                rows.Add((reader.GetString(0), reader.GetString(1), reader.GetInt32(2),
                    (byte[])reader[3], reader.IsDBNull(4) ? null : (byte[])reader[4],
                    reader.GetString(5), reader.GetString(6), reader.GetString(7)));
            }
            rows.Reverse();
            var result = new List<StoredMessage>(rows.Count);
            foreach (var r in rows)
            {
                var env = await _crypto.OpenAsync(_keys.Dek, r.EnvEnc,
                    Encoding.UTF8.GetBytes($"ocs-col-v1:msg-env:{r.Id}"), ct);
                string? pt = null;
                if (r.PtEnc is not null)
                {
                    pt = Encoding.UTF8.GetString(await _crypto.OpenAsync(_keys.Dek, r.PtEnc,
                        Encoding.UTF8.GetBytes($"ocs-col-v1:msg-pt:{r.Id}"), ct));
                }
                result.Add(new StoredMessage(r.Id, r.Conv, env, ParseTime(r.Created),
                    (MessageDirection)r.Dir, r.Status, r.Hash, pt));
            }
            return result;
        }
        finally { _gate.Release(); }
    }

    public async Task<bool> EnvelopeHashExistsAsync(string envelopeHash, CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            await using var cmd = Conn.CreateCommand();
            cmd.CommandText = "SELECT 1 FROM messages WHERE envelope_hash=@hash LIMIT 1";
            cmd.Parameters.AddWithValue("@hash", envelopeHash);
            return await cmd.ExecuteScalarAsync(ct) is not null;
        }
        finally { _gate.Release(); }
    }

    // ── identity + pre-keys ──────────────────────────────────────────────────

    private static readonly byte[] IdentityAad = "ocs-col-v1:identity"u8.ToArray();

    public async Task SaveIdentityAsync(byte[] identityKeyPairBlob, uint registrationId, CancellationToken ct)
    {
        var enc = await _crypto.SealAsync(_keys.Dek, identityKeyPairBlob, IdentityAad, ct);
        await _gate.WaitAsync(ct);
        try
        {
            await using var cmd = Conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO identity_material(id, kind, key_blob_enc, registration_id, key_version, created_at)
                VALUES (1, 'identity', @blob, @reg, 1, @created)
                ON CONFLICT(id) DO UPDATE SET key_blob_enc=@blob, registration_id=@reg, created_at=@created
                """;
            cmd.Parameters.AddWithValue("@blob", enc);
            cmd.Parameters.AddWithValue("@reg", (long)registrationId);
            cmd.Parameters.AddWithValue("@created", DateTimeOffset.UtcNow.ToString("O"));
            await cmd.ExecuteNonQueryAsync(ct);
        }
        finally { _gate.Release(); }
    }

    public async Task<(byte[] IdentityKeyPair, uint RegistrationId)?> LoadIdentityAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            byte[]? enc = null;
            long reg = 0;
            await using var cmd = Conn.CreateCommand();
            cmd.CommandText = "SELECT key_blob_enc, registration_id FROM identity_material WHERE id=1";
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            if (await reader.ReadAsync(ct))
            {
                enc = (byte[])reader[0];
                reg = reader.GetInt64(1);
            }
            if (enc is null) return null;
            var blob = await _crypto.OpenAsync(_keys.Dek, enc, IdentityAad, ct);
            return (blob, (uint)reg);
        }
        finally { _gate.Release(); }
    }

    public Task SaveSignedPreKeyAsync(uint id, byte[] recordBlob, CancellationToken ct) =>
        SavePreKeyAsync("signed", id, recordBlob, ct);

    public Task SaveKyberPreKeyAsync(uint id, byte[] recordBlob, CancellationToken ct) =>
        SavePreKeyAsync("kyber", id, recordBlob, ct);

    private async Task SavePreKeyAsync(string kind, uint id, byte[] recordBlob, CancellationToken ct)
    {
        var enc = await _crypto.SealAsync(_keys.Dek, recordBlob, PreKeyAad(kind, id), ct);
        await _gate.WaitAsync(ct);
        try
        {
            await using var cmd = Conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO prekey_material(key_id, kind, key_blob_enc, consumed_at, key_version)
                VALUES (@key, @kind, @blob, NULL, 1)
                ON CONFLICT(kind, key_id) DO UPDATE SET key_blob_enc=@blob
                """;
            cmd.Parameters.AddWithValue("@key", (long)id);
            cmd.Parameters.AddWithValue("@kind", kind);
            cmd.Parameters.AddWithValue("@blob", enc);
            await cmd.ExecuteNonQueryAsync(ct);
        }
        finally { _gate.Release(); }
    }

    public async Task SaveOneTimePreKeysAsync(IReadOnlyList<PreKeyEntry> entries, CancellationToken ct)
    {
        var sealedEntries = new List<(uint Id, byte[] Enc)>(entries.Count);
        foreach (var e in entries)
        {
            sealedEntries.Add((e.Id, await _crypto.SealAsync(_keys.Dek, e.Record, PreKeyAad("otpk", e.Id), ct)));
        }
        await _gate.WaitAsync(ct);
        try
        {
            await using var tx = (SqliteTransaction)await Conn.BeginTransactionAsync(ct);
            foreach (var (id, enc) in sealedEntries)
            {
                await using var cmd = Conn.CreateCommand();
                cmd.Transaction = tx;
                cmd.CommandText = """
                    INSERT INTO prekey_material(key_id, kind, key_blob_enc, consumed_at, key_version)
                    VALUES (@key, 'otpk', @blob, NULL, 1)
                    ON CONFLICT(kind, key_id) DO UPDATE SET key_blob_enc=@blob
                    """;
                cmd.Parameters.AddWithValue("@key", (long)id);
                cmd.Parameters.AddWithValue("@blob", enc);
                await cmd.ExecuteNonQueryAsync(ct);
            }
            await tx.CommitAsync(ct);
        }
        finally { _gate.Release(); }
    }

    public Task<IReadOnlyList<PreKeyEntry>> GetSignedPreKeysAsync(CancellationToken ct) =>
        GetPreKeysAsync("signed", onlyAvailable: false, ct);

    public Task<IReadOnlyList<PreKeyEntry>> GetKyberPreKeysAsync(CancellationToken ct) =>
        GetPreKeysAsync("kyber", onlyAvailable: false, ct);

    public Task<IReadOnlyList<PreKeyEntry>> GetAvailableOneTimePreKeysAsync(CancellationToken ct) =>
        GetPreKeysAsync("otpk", onlyAvailable: true, ct);

    private async Task<IReadOnlyList<PreKeyEntry>> GetPreKeysAsync(string kind, bool onlyAvailable,
        CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            var rows = new List<(uint Id, byte[] Enc)>();
            await using var cmd = Conn.CreateCommand();
            cmd.CommandText = onlyAvailable
                ? "SELECT key_id, key_blob_enc FROM prekey_material WHERE kind=@kind AND consumed_at IS NULL ORDER BY key_id"
                : "SELECT key_id, key_blob_enc FROM prekey_material WHERE kind=@kind ORDER BY key_id";
            cmd.Parameters.AddWithValue("@kind", kind);
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                rows.Add(((uint)reader.GetInt64(0), (byte[])reader[1]));
            }
            var result = new List<PreKeyEntry>(rows.Count);
            foreach (var (id, enc) in rows)
            {
                result.Add(new PreKeyEntry(id, await _crypto.OpenAsync(_keys.Dek, enc, PreKeyAad(kind, id), ct)));
            }
            return result;
        }
        finally { _gate.Release(); }
    }

    public async Task<int> CountAvailableOneTimePreKeysAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            return (int)await ScalarLongAsync(
                "SELECT count(*) FROM prekey_material WHERE kind='otpk' AND consumed_at IS NULL", ct);
        }
        finally { _gate.Release(); }
    }

    public async Task<uint> NextPreKeyIdAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            var max = await ScalarLongAsync("SELECT coalesce(max(key_id), 0) FROM prekey_material", ct);
            return (uint)(max + 1);
        }
        finally { _gate.Release(); }
    }

    private static byte[] PreKeyAad(string kind, uint id) =>
        Encoding.UTF8.GetBytes($"ocs-col-v1:prekey:{kind}:{id}");

    // ── exchange packages ────────────────────────────────────────────────────

    public async Task RecordExchangePackageAsync(string peerId, string packageHash, int packageVersion,
        string status, CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            await using var cmd = Conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO exchange_packages(peer_id, package_hash, package_version, imported_at, status)
                VALUES (@peer, @hash, @version, @now, @status)
                ON CONFLICT(package_hash) DO UPDATE SET status=@status
                """;
            cmd.Parameters.AddWithValue("@peer", peerId);
            cmd.Parameters.AddWithValue("@hash", packageHash);
            cmd.Parameters.AddWithValue("@version", packageVersion);
            cmd.Parameters.AddWithValue("@now", DateTimeOffset.UtcNow.ToString("O"));
            cmd.Parameters.AddWithValue("@status", status);
            await cmd.ExecuteNonQueryAsync(ct);
        }
        finally { _gate.Release(); }
    }

    public async Task<bool> ExchangePackageExistsAsync(string packageHash, CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            await using var cmd = Conn.CreateCommand();
            cmd.CommandText = "SELECT 1 FROM exchange_packages WHERE package_hash=@hash LIMIT 1";
            cmd.Parameters.AddWithValue("@hash", packageHash);
            return await cmd.ExecuteScalarAsync(ct) is not null;
        }
        finally { _gate.Release(); }
    }

    // ── security events + settings ───────────────────────────────────────────

    public async Task AddSecurityEventAsync(string eventType, string detailsJson, CancellationToken ct)
    {
        var id = Guid.NewGuid().ToString("N");
        var enc = await _crypto.SealAsync(_keys.Dek, Encoding.UTF8.GetBytes(detailsJson),
            Encoding.UTF8.GetBytes($"ocs-col-v1:event:{id}"), ct);
        await _gate.WaitAsync(ct);
        try
        {
            await using var cmd = Conn.CreateCommand();
            cmd.CommandText = "INSERT INTO security_events(id, event_type, details_enc, created_at) VALUES (@id, @type, @details, @created)";
            cmd.Parameters.AddWithValue("@id", id);
            cmd.Parameters.AddWithValue("@type", eventType);
            cmd.Parameters.AddWithValue("@details", enc);
            cmd.Parameters.AddWithValue("@created", DateTimeOffset.UtcNow.ToString("O"));
            await cmd.ExecuteNonQueryAsync(ct);
        }
        finally { _gate.Release(); }
    }

    public async Task<IReadOnlyList<SecurityEventRecord>> GetSecurityEventsAsync(int limit, CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            var result = new List<SecurityEventRecord>();
            await using var cmd = Conn.CreateCommand();
            cmd.CommandText = "SELECT id, event_type, details_enc, created_at FROM security_events ORDER BY created_at DESC, rowid DESC LIMIT @limit";
            cmd.Parameters.AddWithValue("@limit", limit);
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                result.Add(new SecurityEventRecord(reader.GetString(0), reader.GetString(1),
                    (byte[])reader[2], ParseTime(reader.GetString(3))));
            }
            return result;
        }
        finally { _gate.Release(); }
    }

    public async Task SetSettingAsync(string key, string valueJson, CancellationToken ct)
    {
        var enc = await _crypto.SealAsync(_keys.Dek, Encoding.UTF8.GetBytes(valueJson),
            Encoding.UTF8.GetBytes($"ocs-col-v1:setting:{key}"), ct);
        await _gate.WaitAsync(ct);
        try
        {
            await using var cmd = Conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO app_settings(setting_key, value_enc) VALUES (@key, @value)
                ON CONFLICT(setting_key) DO UPDATE SET value_enc=@value
                """;
            cmd.Parameters.AddWithValue("@key", key);
            cmd.Parameters.AddWithValue("@value", enc);
            await cmd.ExecuteNonQueryAsync(ct);
        }
        finally { _gate.Release(); }
    }

    public async Task<string?> GetSettingAsync(string key, CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            byte[]? enc = null;
            await using var cmd = Conn.CreateCommand();
            cmd.CommandText = "SELECT value_enc FROM app_settings WHERE setting_key=@key";
            cmd.Parameters.AddWithValue("@key", key);
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            if (await reader.ReadAsync(ct)) enc = (byte[])reader[0];
            if (enc is null) return null;
            return Encoding.UTF8.GetString(await _crypto.OpenAsync(_keys.Dek, enc,
                Encoding.UTF8.GetBytes($"ocs-col-v1:setting:{key}"), ct));
        }
        finally { _gate.Release(); }
    }

    // ── snapshot for backups ─────────────────────────────────────────────────

    public async Task<byte[]> CreateSnapshotAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            var tmp = Path.Combine(Path.GetDirectoryName(DatabasePath)!,
                "snapshot-" + Guid.NewGuid().ToString("N") + ".db");
            try
            {
                await using var cmd = Conn.CreateCommand();
                cmd.CommandText = "VACUUM INTO @path";
                cmd.Parameters.AddWithValue("@path", tmp);
                await cmd.ExecuteNonQueryAsync(ct);
                return await File.ReadAllBytesAsync(tmp, ct);
            }
            finally
            {
                if (File.Exists(tmp)) File.Delete(tmp);
            }
        }
        finally { _gate.Release(); }
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private async Task<byte[]> SealTextAsync(string text, string aad, CancellationToken ct) =>
        await _crypto.SealAsync(_keys.Dek, Encoding.UTF8.GetBytes(text), Encoding.UTF8.GetBytes(aad), ct);

    private async Task<string> OpenTextAsync(byte[] enc, string aad, CancellationToken ct) =>
        Encoding.UTF8.GetString(await _crypto.OpenAsync(_keys.Dek, enc, Encoding.UTF8.GetBytes(aad), ct));

    private async Task ExecAsync(string sql, CancellationToken ct)
    {
        await using var cmd = Conn.CreateCommand();
        cmd.CommandText = sql;
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private async Task<bool> TableExistsAsync(string name, CancellationToken ct)
    {
        await using var cmd = Conn.CreateCommand();
        cmd.CommandText = "SELECT 1 FROM sqlite_master WHERE type='table' AND name=@name";
        cmd.Parameters.AddWithValue("@name", name);
        return await cmd.ExecuteScalarAsync(ct) is not null;
    }

    private async Task<long> ScalarLongAsync(string sql, CancellationToken ct)
    {
        await using var cmd = Conn.CreateCommand();
        cmd.CommandText = sql;
        var result = await cmd.ExecuteScalarAsync(ct);
        return result is null or DBNull ? 0 : Convert.ToInt64(result, CultureInfo.InvariantCulture);
    }

    private static DateTimeOffset ParseTime(string s) =>
        DateTimeOffset.Parse(s, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;
        if (_conn is not null)
        {
            await _conn.DisposeAsync();
            _conn = null;
        }
        Array.Clear(_keys.DbKey);
        Array.Clear(_keys.Dek);
        _gate.Dispose();
    }
}
