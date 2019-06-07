/// The version number of the library, as declared in the C source.
#[derive(Clone, Copy)]
pub enum CVersion {
    OpenSsl(u64),
    LibreSsl(u64),
    BoringSsl(u64),
}

pub fn get(version: CVersion) -> Vec<&'static str> {
    let mut cfgs = vec![];

    match version {
        CVersion::OpenSsl(openssl_version) => {
            if openssl_version >= 0x1_00_01_00_0 {
                cfgs.push("ossl101");
            }
            if openssl_version >= 0x1_00_02_00_0 {
                cfgs.push("ossl102");
            }
            if openssl_version >= 0x1_00_02_06_0 {
                cfgs.push("ossl102f");
            }
            if openssl_version >= 0x1_00_02_08_0 {
                cfgs.push("ossl102h");
            }
            if openssl_version >= 0x1_01_00_00_0 {
                cfgs.push("ossl110");
            }
            if openssl_version >= 0x1_01_00_06_0 {
                cfgs.push("ossl110f");
            }
            if openssl_version >= 0x1_01_00_07_0 {
                cfgs.push("ossl110g");
            }
            if openssl_version >= 0x1_01_01_00_0 {
                cfgs.push("ossl111");
            }
            if openssl_version >= 0x1_01_01_02_0 {
                cfgs.push("ossl111b");
            }
            if openssl_version >= 0x1_01_01_03_0 {
                cfgs.push("ossl111c");
            }
        }
        CVersion::LibreSsl(libressl_version) => {
            cfgs.push("libressl");

            if libressl_version >= 0x2_05_01_00_0 {
                cfgs.push("libressl251");
            }
            if libressl_version >= 0x2_06_01_00_0 {
                cfgs.push("libressl261");
            }
            if libressl_version >= 0x2_07_00_00_0 {
                cfgs.push("libressl270");
            }
            if libressl_version >= 0x2_07_01_00_0 {
                cfgs.push("libressl271");
            }
            if libressl_version >= 0x2_07_03_00_0 {
                cfgs.push("libressl273");
            }
            if libressl_version >= 0x2_08_00_00_0 {
                cfgs.push("libressl280");
            }
            if libressl_version >= 0x2_08_01_00_0 {
                cfgs.push("libressl281");
            }
            if libressl_version >= 0x2_09_01_00_0 {
                cfgs.push("libressl291");
            }
        }
        CVersion::BoringSsl(_) => {
            cfgs.push("boringssl");
        }
    }

    cfgs
}
