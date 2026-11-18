// OCS Signal bridge — C ABI boundary over the official Signal Protocol stack.
// SPDX-License-Identifier: AGPL-3.0-only
//
// Contract:
//   ocs_call(op, req_json_bytes, req_len, &out_ptr, &out_len) -> status
//     status 0: success; *out_ptr is a UTF-8 JSON response owned by the bridge.
//     status < 0: failure; *out_ptr is a JSON object {"error": "..."}.
//   The caller MUST release every non-null out buffer with ocs_free(ptr, len).
//
// The bridge is stateless: durable state lives in the encrypted C# repository.
// No plaintext, key material or passwords are ever logged here.

#![allow(clippy::missing_safety_doc)]

mod ops;
mod store;

use std::ffi::{c_char, CStr};

/// Bumped whenever the FFI/JSON contract changes.
pub const BRIDGE_VERSION: u32 = 2;

#[no_mangle]
pub extern "C" fn ocs_crypto_bridge_version() -> u32 {
    BRIDGE_VERSION
}

#[no_mangle]
pub extern "C" fn ocs_crypto_bridge_is_ready() -> bool {
    true
}

/// Dispatch one JSON request. Public so integration tests can bypass the FFI.
pub fn dispatch(op: &str, request_json: &str) -> Result<String, String> {
    let req: serde_json::Value =
        serde_json::from_str(request_json).map_err(|e| format!("bad request JSON: {e}"))?;
    let resp = ops::run(op, &req)?;
    serde_json::to_string(&resp).map_err(|e| format!("response serialize: {e}"))
}

#[no_mangle]
pub unsafe extern "C" fn ocs_call(
    op: *const c_char,
    req: *const u8,
    req_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if out.is_null() || out_len.is_null() {
        return -1;
    }
    *out = std::ptr::null_mut();
    *out_len = 0;

    let result = std::panic::catch_unwind(|| {
        if op.is_null() {
            return Err("null op pointer".to_string());
        }
        let op = CStr::from_ptr(op)
            .to_str()
            .map_err(|_| "op is not valid UTF-8".to_string())?;
        let req_bytes: &[u8] = if req_len == 0 {
            &[]
        } else {
            if req.is_null() {
                return Err("null request pointer".to_string());
            }
            if req_len > 64 * 1024 * 1024 {
                return Err("request too large".to_string());
            }
            std::slice::from_raw_parts(req, req_len)
        };
        let req_str =
            std::str::from_utf8(req_bytes).map_err(|_| "request is not valid UTF-8".to_string())?;
        dispatch(op, req_str)
    });

    let (code, body) = match result {
        Ok(Ok(json)) => (0, json),
        Ok(Err(e)) => (-4, serde_json::json!({ "error": e }).to_string()),
        Err(_) => (-5, "{\"error\":\"internal bridge panic\"}".to_string()),
    };

    let bytes = body.into_bytes().into_boxed_slice();
    *out_len = bytes.len();
    *out = Box::into_raw(bytes) as *mut u8;
    code
}

#[no_mangle]
pub unsafe extern "C" fn ocs_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        drop(Box::from_raw(std::slice::from_raw_parts_mut(ptr, len)));
    }
}
