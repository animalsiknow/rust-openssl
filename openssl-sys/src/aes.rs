use libc::*;
use *;

pub const AES_ENCRYPT: c_int = 1;
pub const AES_DECRYPT: c_int = 0;

pub const AES_MAXNR: c_int = 14;
pub const AES_BLOCK_SIZE: c_int = 16;

cfg_if! {
    if #[cfg(boringssl)] {
        pub type Rounds = c_uint;
        pub type AesBits = c_uint;
    } else {
        pub type Rounds = c_int;
        pub type AesBits = c_int;
    }
}

#[repr(C)]
pub struct AES_KEY {
    // There is some business with AES_LONG which is there to ensure the values here are 32 bits
    rd_key: [u32; 4 * (AES_MAXNR as usize + 1)],
    rounds: Rounds,
}

extern "C" {
    pub fn AES_set_encrypt_key(userKey: *const Char, bits: AesBits, key: *mut AES_KEY) -> c_int;
    pub fn AES_set_decrypt_key(userKey: *const Char, bits: AesBits, key: *mut AES_KEY) -> c_int;

    #[cfg(not(boringssl))]
    pub fn AES_ige_encrypt(
        in_: *const Char,
        out: *mut Char,
        length: size_t,
        key: *const AES_KEY,
        ivec: *mut Char,
        enc: c_int,
    );
}
