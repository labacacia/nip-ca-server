// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import * as x509 from "@peculiar/x509";

// Wire @peculiar/x509 to Node's Web Crypto on first import.
x509.cryptoProvider.set(globalThis.crypto);

const PBKDF2_ITERS = 600_000;
const SALT_LEN = 16;
const NONCE_LEN = 12;
const KEY_LEN = 32;

export interface KeyEnvelope {
  version: number;
  algorithm: string;
  pub_key: string;
  salt: string;
  nonce: string;
  ciphertext: string;
}

function deriveKey(passphrase: string, salt: Buffer): Buffer {
  return crypto.pbkdf2Sync(passphrase, salt, PBKDF2_ITERS, KEY_LEN, "sha256");
}

export function pubKeyString(pubKey: crypto.KeyObject): string {
  const raw = pubKey.export({ type: "pkcs8", format: "der" });
  // Ed25519 PKCS8 DER = 44 bytes; raw public key is last 32 bytes
  const rawPub = raw.subarray(raw.length - 32);
  return "ed25519:" + rawPub.toString("hex");
}

function rawPrivateBytes(privKey: crypto.KeyObject): Buffer {
  // Ed25519 private key in JWK → d field is base64url-encoded 32-byte seed
  const jwk = privKey.export({ format: "jwk" }) as { d: string };
  return Buffer.from(jwk.d, "base64url");
}

export function generateKey(): crypto.KeyObject {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  return privateKey;
}

export function saveKey(privKey: crypto.KeyObject, filePath: string, passphrase: string): void {
  const salt = crypto.randomBytes(SALT_LEN);
  const nonce = crypto.randomBytes(NONCE_LEN);
  const dk = deriveKey(passphrase, salt);
  const seed = rawPrivateBytes(privKey);
  const cipher = crypto.createCipheriv("aes-256-gcm", dk, nonce);
  const encrypted = Buffer.concat([cipher.update(seed), cipher.final()]);
  const tag = cipher.getAuthTag();
  const ciphertext = Buffer.concat([encrypted, tag]);
  const { privateKey: tmpPriv, publicKey: tmpPub } = crypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "der" },
    publicKeyEncoding: { type: "spki", format: "der" },
  });
  // Re-derive public key from the same private key
  const pubStr = pubKeyString(crypto.createPublicKey(privKey));
  const envelope: KeyEnvelope = {
    version: 1,
    algorithm: "ed25519",
    pub_key: pubStr,
    salt: salt.toString("hex"),
    nonce: nonce.toString("hex"),
    ciphertext: ciphertext.toString("hex"),
  };
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(envelope), { mode: 0o600 });
}

export function loadKey(filePath: string, passphrase: string): crypto.KeyObject {
  const env: KeyEnvelope = JSON.parse(fs.readFileSync(filePath, "utf8"));
  const salt = Buffer.from(env.salt, "hex");
  const nonce = Buffer.from(env.nonce, "hex");
  const ctBuf = Buffer.from(env.ciphertext, "hex");
  const tag = ctBuf.subarray(ctBuf.length - 16);
  const ciphertext = ctBuf.subarray(0, ctBuf.length - 16);
  const dk = deriveKey(passphrase, salt);
  const decipher = crypto.createDecipheriv("aes-256-gcm", dk, nonce);
  decipher.setAuthTag(tag);
  let seed: Buffer;
  try {
    seed = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new Error("Key decryption failed — wrong passphrase?");
  }
  return crypto.createPrivateKey({ key: seed, format: "der", type: "pkcs8" } as any) ||
    (() => {
      // Construct PKCS8 DER for Ed25519 seed manually
      // PKCS8 for Ed25519 = 0x302e020100300506032b657004220420 + 32-byte seed
      const pkcs8Header = Buffer.from("302e020100300506032b657004220420", "hex");
      const der = Buffer.concat([pkcs8Header, seed]);
      return crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
    })();
}

function canonicalJson(obj: Record<string, unknown>): Buffer {
  const sorted = Object.keys(obj).sort().reduce((acc, k) => {
    (acc as any)[k] = (obj as any)[k];
    return acc;
  }, {} as Record<string, unknown>);
  return Buffer.from(JSON.stringify(sorted), "utf8");
}

export function signDict(privKey: crypto.KeyObject, obj: Record<string, unknown>): string {
  const sig = crypto.sign(null, canonicalJson(obj), privKey);
  return "ed25519:" + sig.toString("base64");
}

export interface IssuedCert {
  nid: string;
  pub_key: string;
  capabilities: string[];
  scope: Record<string, unknown>;
  issued_by: string;
  issued_at: string;
  expires_at: string;
  serial: string;
  signature: string;
  metadata?: Record<string, unknown>;
}

export function issueCert(
  privKey: crypto.KeyObject,
  caNid: string,
  subjectNid: string,
  subjectPubKey: string,
  capabilities: string[],
  scope: Record<string, unknown>,
  validityDays: number,
  serial: string,
  metadata?: Record<string, unknown> | null,
): IssuedCert {
  const now = new Date();
  const expires = new Date(now.getTime() + validityDays * 86400_000);
  const fmt = (d: Date) => d.toISOString().replace(/\.\d{3}Z$/, "Z");
  const unsigned: Record<string, unknown> = {
    capabilities,
    expires_at: fmt(expires),
    issued_at: fmt(now),
    issued_by: caNid,
    nid: subjectNid,
    pub_key: subjectPubKey,
    scope,
    serial,
  };
  const signature = signDict(privKey, unsigned);
  const cert: IssuedCert = { ...unsigned as any, signature };
  if (metadata) cert.metadata = metadata;
  return cert;
}

export function generateNid(domain: string, entityType: string): string {
  const uid = crypto.randomBytes(8).toString("hex");
  return `urn:nps:${entityType}:${domain}:${uid}`;
}

// ── NPS-RFC-0002 X.509 issuance ──────────────────────────────────────────────

// Provisional OIDs — replace once IANA PEN is granted (RFC-0002 §10 OQ-2).
const OID_EKU_AGENT         = "1.3.6.1.4.1.65715.1.1";
const OID_EKU_NODE          = "1.3.6.1.4.1.65715.1.2";
const OID_NID_ASSURANCE_LVL = "1.3.6.1.4.1.65715.2.1";

// PKCS8 / SPKI prefixes for Ed25519 are fixed per RFC 8410. Combined with raw
// 32-byte key bytes they produce a structurally complete DER blob that Web
// Crypto's importKey can consume — needed to bridge node:crypto KeyObjects to
// @peculiar/x509's CryptoKey/CryptoKeyPair API.
const PKCS8_ED25519_PREFIX = Buffer.from(
  "302e020100300506032b657004220420", "hex");
const SPKI_ED25519_PREFIX  = Buffer.from(
  "302a300506032b6570032100", "hex");

function escapeDn(value: string): string {
  return value.replace(/([",+;<>\\])/g, "\\$1");
}

async function importEd25519Pair(privKey: crypto.KeyObject): Promise<CryptoKeyPair> {
  const jwk = privKey.export({ format: "jwk" }) as { d: string; x: string };
  const seed = Buffer.from(jwk.d, "base64url");
  const pub  = Buffer.from(jwk.x, "base64url");
  const subtle = globalThis.crypto.subtle;
  const privateKey = await subtle.importKey(
    "pkcs8",
    new Uint8Array(Buffer.concat([PKCS8_ED25519_PREFIX, seed])).buffer,
    { name: "Ed25519" }, true, ["sign"]);
  const publicKey  = await subtle.importKey(
    "spki",
    new Uint8Array(Buffer.concat([SPKI_ED25519_PREFIX, pub])).buffer,
    { name: "Ed25519" }, true, ["verify"]);
  return { privateKey, publicKey };
}

async function importEd25519PublicFromString(pubKeyString: string): Promise<CryptoKey> {
  if (!pubKeyString.startsWith("ed25519:")) {
    throw new Error(`Unsupported public key format: ${pubKeyString}`);
  }
  const raw = Buffer.from(pubKeyString.slice("ed25519:".length), "hex");
  return await globalThis.crypto.subtle.importKey(
    "spki",
    new Uint8Array(Buffer.concat([SPKI_ED25519_PREFIX, raw])).buffer,
    { name: "Ed25519" }, true, ["verify"]);
}

/** Load a self-signed X.509 root from disk, or create a fresh 5-year root. */
export async function loadOrCreateRootCert(
  caPriv: crypto.KeyObject, caNid: string, rootPath: string,
): Promise<x509.X509Certificate> {
  if (fs.existsSync(rootPath)) {
    const der = fs.readFileSync(rootPath);
    return new x509.X509Certificate(new Uint8Array(der).buffer);
  }
  const caKeys = await importEd25519Pair(caPriv);
  const now = new Date();
  const root = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: crypto.randomBytes(20).toString("hex"),
    name:         `CN=${escapeDn(caNid)}`,
    notBefore:    new Date(now.getTime() - 60_000),
    notAfter:     new Date(now.getTime() + 365 * 5 * 86400_000),
    signingAlgorithm: { name: "Ed25519" },
    keys:         caKeys,
    extensions: [
      new x509.BasicConstraintsExtension(true, undefined, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
    ],
  });
  fs.mkdirSync(path.dirname(rootPath) || ".", { recursive: true });
  fs.writeFileSync(rootPath, Buffer.from(root.rawData));
  return root;
}

async function issueX509Leaf(
  subjectNid:   string,
  subjectPubKey: string,                // "ed25519:<hex>" wire form
  caPriv:       crypto.KeyObject,
  caNid:        string,
  entityType:   string,
  notBefore:    Date,
  notAfter:     Date,
  serial:       string,                  // hex string, no "0x" prefix
): Promise<x509.X509Certificate> {
  const caKeys     = await importEd25519Pair(caPriv);
  const subjectPub = await importEd25519PublicFromString(subjectPubKey);
  const ekuOid     = entityType === "node" ? OID_EKU_NODE : OID_EKU_AGENT;

  // ASN.1 ENUMERATED encoding of assurance level: tag=0x0A, len=0x01, value=0
  // (anonymous default — NPS-RFC-0003).
  const assuranceDer = new Uint8Array([0x0A, 0x01, 0x00]);

  return await x509.X509CertificateGenerator.create({
    serialNumber: serial,
    issuer:       `CN=${escapeDn(caNid)}`,
    subject:      `CN=${escapeDn(subjectNid)}`,
    notBefore, notAfter,
    publicKey:    subjectPub,
    signingAlgorithm: { name: "Ed25519" },
    signingKey:   caKeys.privateKey,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      new x509.ExtendedKeyUsageExtension([ekuOid], true),
      new x509.SubjectAlternativeNameExtension(
        [{ type: "url", value: subjectNid }], false),
      new x509.Extension(OID_NID_ASSURANCE_LVL, false, assuranceDer),
    ],
  });
}

function b64uEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64").replace(/=+$/, "")
    .replace(/\+/g, "-").replace(/\//g, "_");
}

/**
 * Issue a v2 IdentFrame: v1 Ed25519 signature AND a 2-cert X.509 chain
 * (leaf + self-signed root). Non-breaking — v1 verifiers ignore cert_format
 * and cert_chain. NPS-RFC-0002 §4.
 */
export async function issueCertX509(
  caPriv:        crypto.KeyObject,
  caNid:         string,
  caRootCert:    x509.X509Certificate,
  subjectNid:    string,
  subjectPubKey: string,
  entityType:    string,
  capabilities:  string[],
  scope:         Record<string, unknown>,
  validityDays:  number,
  serial:        string,
  metadata?:     Record<string, unknown> | null,
): Promise<IssuedCert & { cert_format: string; cert_chain: string[] }> {
  const v1 = issueCert(caPriv, caNid, subjectNid, subjectPubKey,
    capabilities, scope, validityDays, serial, metadata);

  const leaf = await issueX509Leaf(
    subjectNid, subjectPubKey, caPriv, caNid, entityType,
    new Date(v1.issued_at),
    new Date(v1.expires_at),
    serial,
  );
  const chain = [
    b64uEncode(new Uint8Array(leaf.rawData)),
    b64uEncode(new Uint8Array(caRootCert.rawData)),
  ];
  return { ...v1, cert_format: "v2-x509", cert_chain: chain };
}
