// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{SigningKey, VerifyingKey};
use pbkdf2::pbkdf2_hmac;
use rand::{rngs::OsRng, RngCore};
use serde_json::{Map, Value};
use sha2::Sha256;
use std::{collections::BTreeMap, fs, path::Path, time::{Duration, SystemTime, UNIX_EPOCH}};

const PBKDF2_ITERS: u32 = 600_000;
const SALT_LEN:     usize = 16;
const NONCE_LEN:    usize = 12;
const KEY_LEN:      usize = 32;

pub struct Ca {
    pub signing_key:   SigningKey,
    pub pub_key_str:   String,
}

// ── Key Management ─────────────────────────────────────────────────────────

pub fn generate_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

pub fn pub_key_string(vk: &VerifyingKey) -> String {
    format!("ed25519:{}", hex::encode(vk.as_bytes()))
}

pub fn save_key(sk: &SigningKey, path: &str, passphrase: &str) -> Result<()> {
    let mut salt  = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let mut dk = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), &salt, PBKDF2_ITERS, &mut dk);

    let cipher = Aes256Gcm::new_from_slice(&dk)?;
    let n = Nonce::from_slice(&nonce);
    let ciphertext = cipher.encrypt(n, sk.as_bytes().as_ref())
        .map_err(|e| anyhow!("encrypt: {e}"))?;

    let vk = sk.verifying_key();
    let envelope = serde_json::json!({
        "version":    1,
        "algorithm":  "ed25519",
        "pub_key":    pub_key_string(&vk),
        "salt":       hex::encode(salt),
        "nonce":      hex::encode(nonce),
        "ciphertext": hex::encode(&ciphertext),
    });
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_string_pretty(&envelope)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn load_key(path: &str, passphrase: &str) -> Result<SigningKey> {
    let data = fs::read_to_string(path)?;
    let env: serde_json::Value = serde_json::from_str(&data)?;
    let salt  = hex::decode(env["salt"].as_str().unwrap_or(""))?;
    let nonce = hex::decode(env["nonce"].as_str().unwrap_or(""))?;
    let ct    = hex::decode(env["ciphertext"].as_str().unwrap_or(""))?;

    let mut dk = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), &salt, PBKDF2_ITERS, &mut dk);

    let cipher = Aes256Gcm::new_from_slice(&dk)?;
    let n = Nonce::from_slice(&nonce);
    let seed = cipher.decrypt(n, ct.as_ref())
        .map_err(|_| anyhow!("Key decryption failed — wrong passphrase?"))?;
    let seed_arr: [u8; 32] = seed.try_into().map_err(|_| anyhow!("invalid seed length"))?;
    Ok(SigningKey::from_bytes(&seed_arr))
}

// ── Signing ────────────────────────────────────────────────────────────────

pub fn canonical_json(obj: &Map<String, Value>) -> Vec<u8> {
    let sorted: BTreeMap<_, _> = obj.iter().collect();
    serde_json::to_vec(&sorted).unwrap_or_default()
}

pub fn sign_dict(sk: &SigningKey, obj: &Map<String, Value>) -> String {
    use ed25519_dalek::Signer;
    let sig = sk.sign(&canonical_json(obj));
    format!("ed25519:{}", B64.encode(sig.to_bytes()))
}

// ── Certificate Issuance ───────────────────────────────────────────────────

fn iso_now_plus(days: i64) -> (String, String) {
    let now_secs = SystemTime::now().duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO).as_secs();
    let exp_secs = now_secs + (days as u64) * 86400;
    (fmt_iso(now_secs), fmt_iso(exp_secs))
}

fn fmt_iso(secs: u64) -> String {
    // Simple ISO 8601 formatter (UTC)
    let s = secs;
    let (y, mo, d, h, mi, sec) = epoch_to_parts(s);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, mi, sec)
}

pub fn epoch_to_parts(secs: u64) -> (u64, u64, u64, u64, u64, u64) {
    let sec   = secs % 60;
    let mins  = secs / 60;
    let mi    = mins % 60;
    let hours = mins / 60;
    let h     = hours % 24;
    let days  = hours / 24;
    // Gregorian calendar calculation
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z.wrapping_sub(146_096) } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y   = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp  = (5 * doy + 2) / 153;
    let d   = doy - (153 * mp + 2) / 5 + 1;
    let mo  = if mp < 10 { mp + 3 } else { mp - 9 };
    let y   = if mo <= 2 { y + 1 } else { y };
    (y, mo, d, h, mi, sec)
}

pub fn issue_cert(
    sk: &SigningKey,
    ca_nid: &str,
    subject_nid: &str,
    subject_pub_key: &str,
    capabilities: Vec<String>,
    scope: Map<String, Value>,
    validity_days: i64,
    serial: &str,
    metadata: Option<Map<String, Value>>,
) -> Map<String, Value> {
    let (issued_at, expires_at) = iso_now_plus(validity_days);
    let mut unsigned = Map::new();
    unsigned.insert("capabilities".into(), Value::Array(capabilities.iter().map(|s| Value::String(s.clone())).collect()));
    unsigned.insert("expires_at".into(),   Value::String(expires_at.clone()));
    unsigned.insert("issued_at".into(),    Value::String(issued_at.clone()));
    unsigned.insert("issued_by".into(),    Value::String(ca_nid.to_string()));
    unsigned.insert("nid".into(),          Value::String(subject_nid.to_string()));
    unsigned.insert("pub_key".into(),      Value::String(subject_pub_key.to_string()));
    unsigned.insert("scope".into(),        Value::Object(scope));
    unsigned.insert("serial".into(),       Value::String(serial.to_string()));

    let signature = sign_dict(sk, &unsigned);
    let mut cert = unsigned;
    cert.insert("signature".into(), Value::String(signature));
    if let Some(meta) = metadata {
        cert.insert("metadata".into(), Value::Object(meta));
    }
    cert
}

pub fn generate_nid(domain: &str, entity_type: &str) -> String {
    let mut uid = [0u8; 8];
    OsRng.fill_bytes(&mut uid);
    format!("urn:nps:{}:{}:{}", entity_type, domain, hex::encode(uid))
}

// ── NPS-RFC-0002 X.509 issuance ──────────────────────────────────────────────

use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType, IsCa,
    KeyPair, KeyUsagePurpose, SanType, SerialNumber, SubjectPublicKeyInfo,
};
use std::path::PathBuf;

// Provisional OIDs — replace once IANA PEN is granted (RFC-0002 §10 OQ-2).
const OID_EKU_AGENT:        &[u64] = &[1, 3, 6, 1, 4, 1, 65715, 1, 1];
const OID_EKU_NODE:         &[u64] = &[1, 3, 6, 1, 4, 1, 65715, 1, 2];
const OID_NID_ASSURANCE:    &[u64] = &[1, 3, 6, 1, 4, 1, 65715, 2, 1];
const OID_EXT_KEY_USAGE:    &[u64] = &[2, 5, 29, 37];

fn dalek_to_rcgen_keypair(sk: &SigningKey) -> Result<KeyPair> {
    let mut pkcs8 = Vec::with_capacity(48);
    pkcs8.extend_from_slice(&[
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
        0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    ]);
    pkcs8.extend_from_slice(sk.as_bytes());
    KeyPair::try_from(pkcs8.as_slice()).map_err(|e| anyhow!("dalek→rcgen keypair: {e}"))
}

fn raw_pub_to_spki(pub_raw: &[u8; 32]) -> Result<SubjectPublicKeyInfo> {
    let mut spki = Vec::with_capacity(44);
    spki.extend_from_slice(&[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
        0x70, 0x03, 0x21, 0x00,
    ]);
    spki.extend_from_slice(pub_raw);
    SubjectPublicKeyInfo::from_der(&spki).map_err(|e| anyhow!("raw pubkey → SPKI: {e}"))
}

fn parse_pub_key_string(s: &str) -> Result<[u8; 32]> {
    let prefix = "ed25519:";
    if !s.starts_with(prefix) {
        return Err(anyhow!("unsupported public key format: {s}"));
    }
    let raw = hex::decode(&s[prefix.len()..]).map_err(|e| anyhow!("hex decode: {e}"))?;
    if raw.len() != 32 {
        return Err(anyhow!("public key wrong size: {}", raw.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn sys_to_offset(t: SystemTime) -> time::OffsetDateTime {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    time::OffsetDateTime::from_unix_timestamp(d.as_secs() as i64)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
}

fn iso_to_systime(iso: &str) -> SystemTime {
    let s = iso.trim_end_matches('Z');
    let parts: Vec<u64> = s.split(['T','-',':']).filter_map(|p| p.parse().ok()).collect();
    if parts.len() < 6 { return SystemTime::now(); }
    let (y, mo, d, h, mi, sec) = (parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]);
    let secs = days_since_epoch_local(y, mo, d) * 86400 + h * 3600 + mi * 60 + sec;
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn days_since_epoch_local(y: u64, mo: u64, d: u64) -> u64 {
    let (y, mo) = if mo <= 2 { (y-1, mo+9) } else { (y, mo-3) };
    let era = y / 400;
    let yoe = y - era*400;
    let doy = (153*mo+2)/5 + d - 1;
    let doe = yoe*365 + yoe/4 - yoe/100 + doy;
    era*146_097 + doe - 719_468
}

fn random_serial() -> Vec<u8> {
    let mut b = vec![0u8; 20];
    OsRng.fill_bytes(&mut b);
    b
}

fn encode_oid_content(oid: &[u64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(oid.len() * 2);
    if oid.len() < 2 { return out; }
    out.push((oid[0] * 40 + oid[1]) as u8);
    for &n in &oid[2..] {
        if n < 128 {
            out.push(n as u8);
        } else {
            let mut bytes = Vec::new();
            let mut v = n;
            bytes.push((v & 0x7F) as u8);
            v >>= 7;
            while v > 0 {
                bytes.push(((v & 0x7F) | 0x80) as u8);
                v >>= 7;
            }
            bytes.reverse();
            out.extend(bytes);
        }
    }
    out
}

fn build_eku_extension_value(eku_oid: &[u64]) -> Vec<u8> {
    let oid_content = encode_oid_content(eku_oid);
    let mut oid_tlv = Vec::with_capacity(2 + oid_content.len());
    oid_tlv.push(0x06);
    oid_tlv.push(oid_content.len() as u8);
    oid_tlv.extend(oid_content);
    let mut seq = Vec::with_capacity(2 + oid_tlv.len());
    seq.push(0x30);
    seq.push(oid_tlv.len() as u8);
    seq.extend(oid_tlv);
    seq
}

/// Build a self-signed X.509 root cert from the existing CA Ed25519 key and
/// persist the DER to `root_path` for external observability.
///
/// Unlike the other CA Server reference ports, this function does NOT attempt
/// to load a previously persisted cert: `rcgen::Certificate` cannot be
/// reconstructed from raw DER, so a fresh cert is re-issued on every boot
/// (same key, new validity window). The DER at `root_path` is informational
/// only — do NOT byte-pin it; pin the CA's Ed25519 public key instead.
pub fn create_root_cert_and_persist(
    sk: &SigningKey, ca_nid: &str, root_path: &str,
) -> Result<rcgen::Certificate> {
    let ca_keypair = dalek_to_rcgen_keypair(sk)?;
    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| anyhow!("rcgen params: {e}"))?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, ca_nid.to_string());
    params.distinguished_name = dn;
    params.serial_number = Some(SerialNumber::from_slice(&[1]));
    let now = SystemTime::now();
    params.not_before = sys_to_offset(now - Duration::from_secs(60));
    params.not_after  = sys_to_offset(now + Duration::from_secs(5 * 365 * 24 * 3600));
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    let cert = params.self_signed(&ca_keypair)
        .map_err(|e| anyhow!("rcgen self_signed: {e}"))?;
    let dir = PathBuf::from(root_path);
    if let Some(parent) = dir.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(root_path, cert.der().as_ref());
    Ok(cert)
}

/// Issue a v2 IdentFrame: v1 Ed25519 signature AND a 2-cert X.509 chain
/// (leaf + self-signed root). Non-breaking — v1 verifiers ignore
/// cert_format/cert_chain. NPS-RFC-0002 §4.
#[allow(clippy::too_many_arguments)]
pub fn issue_cert_x509(
    sk: &SigningKey,
    ca_nid: &str,
    ca_root: &rcgen::Certificate,
    subject_nid: &str,
    subject_pub_key: &str,
    entity_type: &str,
    capabilities: Vec<String>,
    scope: Map<String, Value>,
    validity_days: i64,
    serial: &str,
    metadata: Option<Map<String, Value>>,
) -> Result<Map<String, Value>> {
    let v1 = issue_cert(sk, ca_nid, subject_nid, subject_pub_key,
        capabilities, scope, validity_days, serial, metadata);

    let subject_pub_raw = parse_pub_key_string(subject_pub_key)?;
    let subject_spki = raw_pub_to_spki(&subject_pub_raw)?;
    let ca_keypair = dalek_to_rcgen_keypair(sk)?;
    let issued_at  = v1["issued_at"].as_str().unwrap_or("");
    let expires_at = v1["expires_at"].as_str().unwrap_or("");
    let not_before = iso_to_systime(issued_at);
    let not_after  = iso_to_systime(expires_at);

    let eku_oid: &[u64] = if entity_type == "node" { OID_EKU_NODE } else { OID_EKU_AGENT };
    let mut eku_ext = CustomExtension::from_oid_content(
        OID_EXT_KEY_USAGE, build_eku_extension_value(eku_oid));
    eku_ext.set_criticality(true);
    let assurance_ext = CustomExtension::from_oid_content(
        OID_NID_ASSURANCE, vec![0x0A, 0x01, 0x00]);

    let mut params = CertificateParams::new(vec![subject_nid.to_string()])
        .map_err(|e| anyhow!("leaf params: {e}"))?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, subject_nid.to_string());
    params.distinguished_name = dn;
    params.subject_alt_names = vec![SanType::URI(
        subject_nid.try_into().map_err(|e: rcgen::Error| anyhow!("SAN URI: {e}"))?,
    )];
    let serial_bytes = hex::decode(serial.trim_start_matches("0x"))
        .unwrap_or_else(|_| random_serial());
    params.serial_number = Some(SerialNumber::from_slice(&serial_bytes));
    params.not_before = sys_to_offset(not_before);
    params.not_after  = sys_to_offset(not_after);
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.custom_extensions = vec![eku_ext, assurance_ext];

    let leaf = params.signed_by(&subject_spki, ca_root, &ca_keypair)
        .map_err(|e| anyhow!("rcgen signed_by: {e}"))?;

    let mut out = v1;
    out.insert("cert_format".into(), Value::String("v2-x509".into()));
    let chain = vec![
        Value::String(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(leaf.der().as_ref())),
        Value::String(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ca_root.der().as_ref())),
    ];
    out.insert("cert_chain".into(), Value::Array(chain));
    Ok(out)
}
