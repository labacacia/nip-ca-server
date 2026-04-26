// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";

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
