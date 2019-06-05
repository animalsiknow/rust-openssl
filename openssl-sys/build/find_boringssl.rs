use boringssl_src;
use std::path::PathBuf;

pub fn get_openssl(_target: &str) -> (PathBuf, PathBuf) {
    let artifacts = boringssl_src::build();

    (artifacts.lib_dir, artifacts.include_dir)
}
