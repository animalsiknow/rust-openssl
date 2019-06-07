use libc::*;
use std::mem;
use std::ptr;

use *;

pub const TLS1_VERSION: c_int = 0x301;
pub const TLS1_1_VERSION: c_int = 0x302;
pub const TLS1_2_VERSION: c_int = 0x303;
#[cfg(ossl111)]
pub const TLS1_3_VERSION: c_int = 0x304;

pub const TLS1_AD_DECODE_ERROR: c_int = 50;
pub const TLS1_AD_UNRECOGNIZED_NAME: c_int = 112;

pub const TLSEXT_NAMETYPE_host_name: c_int = 0;
pub const TLSEXT_STATUSTYPE_ocsp: c_int = 1;

extern "C" {
    pub fn SSL_get_servername(ssl: *const SSL, name_type: c_int) -> *const c_char;

    pub fn SSL_export_keying_material(
        s: *mut SSL,
        out: *mut c_uchar,
        olen: size_t,
        label: *const c_char,
        llen: size_t,
        context: *const c_uchar,
        contextlen: size_t,
        use_context: c_int,
    ) -> c_int;

    #[cfg(ossl111)]
    pub fn SSL_export_keying_material_early(
        s: *mut ::SSL,
        out: *mut c_uchar,
        olen: size_t,
        label: *const c_char,
        llen: size_t,
        context: *const c_uchar,
        contextlen: size_t,
    ) -> c_int;
}

cfg_if! {
    if #[cfg(boringssl)] {
        extern "C" {
            pub fn SSL_set_tlsext_host_name(s: *mut SSL, name: *const c_char) -> ResultCode;
            pub fn SSL_set_tlsext_status_type(s: *mut SSL, type_: c_int) -> ResultCode;
            pub fn SSL_get_tlsext_status_ocsp_resp(
                ssl: *mut SSL,
                resp: *mut *const u8,
            ) -> SizeResult;
            pub fn SSL_set_tlsext_status_ocsp_resp(
                ssl: *mut SSL,
                resp: *mut u8,
                len: SizeForSslCtrl,
            ) -> ResultCode;
        }
    } else {
        pub unsafe fn SSL_set_tlsext_host_name(s: *mut SSL, name: *mut c_char) -> ResultCode {
            SSL_ctrl(
                s,
                SSL_CTRL_SET_TLSEXT_HOSTNAME,
                TLSEXT_NAMETYPE_host_name as c_long,
                name as *mut c_void,
            )
        }

        pub unsafe fn SSL_set_tlsext_status_type(s: *mut SSL, type_: c_int) -> ResultCode {
            SSL_ctrl(
                s,
                SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE,
                type_ as c_long,
                ptr::null_mut(),
            )
        }

        pub unsafe fn SSL_get_tlsext_status_ocsp_resp(
            ssl: *mut SSL,
            resp: *mut *mut c_uchar,
        ) -> SizeResult {
            SizeResult(SSL_ctrl(
                ssl,
                SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP,
                0,
                resp as *mut c_void,
            ))
        }

        pub unsafe fn SSL_set_tlsext_status_ocsp_resp(
            ssl: *mut SSL,
            resp: *mut c_uchar,
            len: SizeForSslCtrl,
        ) -> ResultCode {
            SSL_ctrl(
                ssl,
                SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP,
                len,
                resp as *mut c_void,
            )
        }
    }
}


type ServerNameCallback = Option<unsafe extern "C" fn(*mut SSL, *mut c_int, *mut c_void) -> c_int>;
type StatusCallback = Option<unsafe extern "C" fn(*mut SSL, *mut c_void) -> c_int>;

cfg_if! {
    if #[cfg(boringssl)] {
        extern "C" {
            pub fn SSL_CTX_set_tlsext_servername_callback(
                ctx: *mut SSL_CTX,
                cb: ServerNameCallback,
            ) -> ResultCode;

            pub fn SSL_CTX_set_tlsext_servername_arg(
                ctx: *mut SSL_CTX,
                arg: *mut c_void,
            ) -> ResultCode;

            pub fn SSL_CTX_set_tlsext_status_cb(
                ctx: *mut SSL_CTX,
                cb: StatusCallback,
            ) -> ResultCode;

            pub fn SSL_CTX_set_tlsext_status_arg(ctx: *mut SSL_CTX, arg: *mut c_void) -> ResultCode;
        }
    } else {
        pub unsafe fn SSL_CTX_set_tlsext_servername_callback(
            ctx: *mut SSL_CTX,
            cb: ServerNameCallback,
        ) -> ResultCode {
            SSL_CTX_callback_ctrl(ctx, SSL_CTRL_SET_TLSEXT_SERVERNAME_CB, mem::transmute(cb))
        }

        pub unsafe fn SSL_CTX_set_tlsext_servername_arg(
            ctx: *mut SSL_CTX,
            arg: *mut c_void,
        ) -> ResultCode {
            SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG, 0, arg)
        }

        pub unsafe fn SSL_CTX_set_tlsext_status_cb(
            ctx: *mut SSL_CTX,
            cb: StatusCallback,
        ) -> ResultCode {
            SSL_CTX_callback_ctrl(ctx, SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB, mem::transmute(cb))
        }

        pub unsafe fn SSL_CTX_set_tlsext_status_arg(
            ctx: *mut SSL_CTX,
            arg: *mut c_void,
        ) -> ResultCode {
            SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG, 0, arg)
        }
    }
}

pub const SSL_TLSEXT_ERR_OK: c_int = 0;
pub const SSL_TLSEXT_ERR_ALERT_WARNING: c_int = 1;
pub const SSL_TLSEXT_ERR_ALERT_FATAL: c_int = 2;
pub const SSL_TLSEXT_ERR_NOACK: c_int = 3;
