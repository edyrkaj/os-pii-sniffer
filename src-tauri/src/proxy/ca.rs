use std::fs;
use std::path::{Path, PathBuf};

use hudsucker::certificate_authority::RcgenAuthority;
use hudsucker::rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use hudsucker::rustls::crypto::CryptoProvider;
use hudsucker::rustls::crypto::aws_lc_rs::default_provider;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub struct CaPaths {
    pub dir: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
}

pub fn ensure_ca(dir: &Path) -> Result<CaPaths, String> {
    fs::create_dir_all(dir).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    let paths = CaPaths {
        dir: dir.to_path_buf(),
        cert: dir.join("ca.cert.pem"),
        key: dir.join("ca.key.pem"),
    };
    if paths.cert.exists() && paths.key.exists() {
        return Ok(paths);
    }
    let key_pair = KeyPair::generate().map_err(|error| error.to_string())?;
    let mut params = CertificateParams::default();
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "PII Sniffer Local CA");
    name.push(DnType::OrganizationName, "PII Sniffer");
    params.distinguished_name = name;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.use_authority_key_identifier_extension = true;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|error| error.to_string())?;
    fs::write(&paths.cert, cert.pem()).map_err(|error| error.to_string())?;
    write_secret(&paths.key, &key_pair.serialize_pem())?;
    Ok(paths)
}

pub fn load_authority(paths: &CaPaths) -> Result<RcgenAuthority, String> {
    let cert_pem = fs::read_to_string(&paths.cert).map_err(|error| error.to_string())?;
    let key_pem = fs::read_to_string(&paths.key).map_err(|error| error.to_string())?;
    let key_pair = KeyPair::from_pem(&key_pem).map_err(|error| error.to_string())?;
    // RcgenAuthority keeps a 'static borrow of the certificate PEM for the process lifetime.
    let cert_static: &'static str = Box::leak(cert_pem.into_boxed_str());
    let issuer =
        Issuer::from_ca_cert_pem(cert_static, key_pair).map_err(|error| error.to_string())?;
    let provider = crypto_provider();
    Ok(RcgenAuthority::new(issuer, 1_000, provider))
}

pub fn crypto_provider() -> CryptoProvider {
    let provider = default_provider();
    let _ = provider.clone().install_default();
    provider
}

fn write_secret(path: &Path, pem: &str) -> Result<(), String> {
    fs::write(path, pem).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}
