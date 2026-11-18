using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using OCS.Core.Models;

namespace OCS.Services.Crypto;

// P/Invoke boundary to the Rust crypto bridge (official Signal Protocol stack).
// The bridge is stateless: one JSON request in, one JSON response out. Every
// native buffer is freed immediately; no key material is logged.
internal static class NativeBridge
{
    private const string Dll = "ocs_signal_bridge";

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int ocs_call(
        byte[] op, byte[] req, nuint reqLen, out IntPtr outPtr, out nuint outLen);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern void ocs_free(IntPtr ptr, nuint len);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern uint ocs_crypto_bridge_version();

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.I1)]
    private static extern bool ocs_crypto_bridge_is_ready();

    public static uint Version => ocs_crypto_bridge_version();

    public static void EnsureReady()
    {
        if (!ocs_crypto_bridge_is_ready())
        {
            throw new CryptoException("bridge_not_ready",
                "The native crypto bridge reports not-ready. Refusing to continue (fail closed).");
        }
    }

    // Runs one bridge operation on a thread-pool thread (Argon2id and protocol
    // work are CPU-heavy; never block the UI thread).
    public static Task<JsonDocument> CallAsync(string op, object request, CancellationToken ct)
    {
        return Task.Run(() => Call(op, request), ct);
    }

    public static JsonDocument Call(string op, object request)
    {
        var reqJson = JsonSerializer.Serialize(request);
        var reqBytes = Encoding.UTF8.GetBytes(reqJson);
        var opBytes = Encoding.UTF8.GetBytes(op + "\0");

        var status = ocs_call(opBytes, reqBytes, (nuint)reqBytes.Length,
            out var outPtr, out var outLen);

        string body;
        if (outPtr == IntPtr.Zero || outLen == 0)
        {
            body = "{}";
        }
        else
        {
            var managed = new byte[(int)outLen];
            Marshal.Copy(outPtr, managed, 0, managed.Length);
            ocs_free(outPtr, outLen);
            body = Encoding.UTF8.GetString(managed);
        }

        if (status != 0)
        {
            var message = TryExtractError(body) ?? $"bridge call '{op}' failed with status {status}";
            throw new CryptoException(status == -5 ? "bridge_panic" : "crypto_error", message);
        }

        try
        {
            return JsonDocument.Parse(body);
        }
        catch (JsonException e)
        {
            throw new CryptoException("bridge_response", $"invalid bridge response: {e.Message}");
        }
    }

    private static string? TryExtractError(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            return doc.RootElement.TryGetProperty("error", out var err) ? err.GetString() : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
