// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import Fastify from "fastify";
import { CaDb } from "./db.js";
import * as ca from "./ca.js";

// ── Config ────────────────────────────────────────────────────────────────────
const CA_NID         = process.env["NIP_CA_NID"]!;
const CA_PASSPHRASE  = process.env["NIP_CA_PASSPHRASE"]!;
const CA_BASE_URL    = (process.env["NIP_CA_BASE_URL"] ?? "").replace(/\/$/, "");
const KEY_FILE       = process.env["NIP_CA_KEY_FILE"]      ?? "/data/ca.key.enc";
const ROOT_CERT_FILE = process.env["NIP_CA_ROOT_CERT_FILE"] ?? "/data/ca.root.der";
const DB_PATH        = process.env["NIP_CA_DB_PATH"]       ?? "/data/ca.db";
const DISPLAY_NAME   = process.env["NIP_CA_DISPLAY_NAME"]  ?? "NPS CA";
const AGENT_DAYS     = parseInt(process.env["NIP_CA_AGENT_VALIDITY_DAYS"] ?? "30");
const NODE_DAYS      = parseInt(process.env["NIP_CA_NODE_VALIDITY_DAYS"]  ?? "90");
const RENEWAL_DAYS   = parseInt(process.env["NIP_CA_RENEWAL_WINDOW_DAYS"] ?? "7");
const PORT           = parseInt(process.env["PORT"] ?? "17440");
const OPERATOR_API_KEY = process.env["NIP_CA_OPERATOR_API_KEY"] ?? "";

for (const k of ["NIP_CA_NID", "NIP_CA_PASSPHRASE", "NIP_CA_BASE_URL"]) {
  if (!process.env[k]) throw new Error(`${k} is required`);
}

const CA_DOMAIN = CA_NID.split(":").slice(-2)[0] ?? "ca.local";

const VALID_REVOKE_REASONS = new Set([
  "key_compromise", "ca_compromise", "affiliation_changed",
  "superseded", "cessation_of_operation",
]);

// ── Bootstrap ─────────────────────────────────────────────────────────────────
let caPriv: crypto.KeyObject;
let caPubStr: string;

if (!fs.existsSync(KEY_FILE)) {
  caPriv = ca.generateKey();
  ca.saveKey(caPriv, KEY_FILE, CA_PASSPHRASE);
} else {
  caPriv = ca.loadKey(KEY_FILE, CA_PASSPHRASE);
}
caPubStr = ca.pubKeyString(crypto.createPublicKey(caPriv));

// NPS-RFC-0002 — load or generate the X.509 root cert (5-year self-signed).
const caRootCert = await ca.loadOrCreateRootCert(caPriv, CA_NID, ROOT_CERT_FILE);

const db = new CaDb(DB_PATH);

// ── Server ─────────────────────────────────────────────────────────────────────
const app = Fastify({ logger: true });

// ── Auth ──────────────────────────────────────────────────────────────────────
function isAuthorized(req: any): boolean {
  if (!OPERATOR_API_KEY) return true;
  const auth: string | undefined = req.headers["authorization"];
  if (!auth || !auth.startsWith("Bearer ")) return false;
  const provided = auth.slice("Bearer ".length);
  try {
    return crypto.timingSafeEqual(
      Buffer.from(provided, "utf8"),
      Buffer.from(OPERATOR_API_KEY, "utf8"),
    );
  } catch {
    return false;
  }
}

function unauthorizedReply(reply: any): void {
  reply.code(401).send({ error_code: "NIP-CA-UNAUTHORIZED",
    message: "Valid operator Bearer token required." });
}

// ── Helpers ────────────────────────────────────────────────────────────────────
function validateRegister(body: any, reply: any): boolean {
  if (!body.pub_key || !body.pub_key.startsWith("ed25519:") || body.pub_key.length <= 8) {
    reply.code(400).send({ error_code: "NIP-CA-BAD-REQUEST",
      message: "pub_key must be 'ed25519:<base64url>'." });
    return false;
  }
  return true;
}

function register(
  body: { nid?: string; pub_key: string; capabilities?: string[]; scope?: object; metadata?: object },
  entityType: string,
  validityDays: number,
  reply: any,
): void {
  if (!validateRegister(body, reply)) return;
  const nid = body.nid ?? ca.generateNid(CA_DOMAIN, entityType);
  if (db.getActive(nid)) {
    reply.code(409).send({ error_code: "NIP-CA-NID-ALREADY-EXISTS",
      message: `${nid} already has an active certificate` });
    return;
  }
  const serial = db.nextSerial();
  const cert = ca.issueCert(caPriv, CA_NID, nid, body.pub_key,
    body.capabilities ?? [], body.scope as any ?? {}, validityDays, serial,
    (body as any).metadata ?? null);
  db.insert({ nid, entity_type: entityType, serial, pub_key: body.pub_key,
    capabilities: body.capabilities ?? [], scope: body.scope as any ?? {},
    issued_by: CA_NID, issued_at: cert.issued_at, expires_at: cert.expires_at,
    metadata: (body as any).metadata ?? null });
  reply.code(201).send({ nid, serial, issued_at: cert.issued_at,
    expires_at: cert.expires_at, ident_frame: cert });
}

async function registerX509(
  body: { nid?: string; pub_key: string; capabilities?: string[]; scope?: object; metadata?: object },
  entityType: string,
  validityDays: number,
  reply: any,
): Promise<void> {
  if (!validateRegister(body, reply)) return;
  const nid = body.nid ?? ca.generateNid(CA_DOMAIN, entityType);
  if (db.getActive(nid)) {
    reply.code(409).send({ error_code: "NIP-CA-NID-ALREADY-EXISTS",
      message: `${nid} already has an active certificate` });
    return;
  }
  const serial = db.nextSerial();
  const cert = await ca.issueCertX509(caPriv, CA_NID, caRootCert, nid, body.pub_key,
    entityType, body.capabilities ?? [], body.scope as any ?? {},
    validityDays, serial, (body as any).metadata ?? null);
  db.insert({ nid, entity_type: entityType, serial, pub_key: body.pub_key,
    capabilities: body.capabilities ?? [], scope: body.scope as any ?? {},
    issued_by: CA_NID, issued_at: cert.issued_at, expires_at: cert.expires_at,
    metadata: (body as any).metadata ?? null });
  reply.code(201).send({ nid, serial, issued_at: cert.issued_at,
    expires_at: cert.expires_at, ident_frame: cert });
}

// ── Routes ─────────────────────────────────────────────────────────────────────
app.post("/v1/agents/register", async (req, reply) => {
  if (!isAuthorized(req)) return unauthorizedReply(reply);
  register(req.body as any, "agent", AGENT_DAYS, reply);
});

app.post("/v1/nodes/register", async (req, reply) => {
  if (!isAuthorized(req)) return unauthorizedReply(reply);
  register(req.body as any, "node", NODE_DAYS, reply);
});

// ── register-x509 (NPS-RFC-0002 X.509 + Ed25519 dual-trust) ──────────────────
app.post("/v1/agents/register-x509", async (req, reply) => {
  if (!isAuthorized(req)) return unauthorizedReply(reply);
  await registerX509(req.body as any, "agent", AGENT_DAYS, reply);
});

app.post("/v1/nodes/register-x509", async (req, reply) => {
  if (!isAuthorized(req)) return unauthorizedReply(reply);
  await registerX509(req.body as any, "node", NODE_DAYS, reply);
});

// ── Agent lifecycle ───────────────────────────────────────────────────────────
app.post<{ Params: { nid: string } }>("/v1/agents/:nid/renew", async (req, reply) => {
  if (!isAuthorized(req)) return unauthorizedReply(reply);
  const nid = req.params.nid;
  const rec = db.getActive(nid);
  if (!rec) return reply.code(404).send({ error_code: "NIP-CA-NID-NOT-FOUND", message: `${nid} not found` });
  const expMs = new Date(rec.expires_at).getTime();
  const daysLeft = Math.floor((expMs - Date.now()) / 86400_000);
  if (daysLeft > RENEWAL_DAYS)
    return reply.code(400).send({ error_code: "NIP-CA-RENEWAL-TOO-EARLY",
      message: `Renewal window opens in ${daysLeft - RENEWAL_DAYS} days` });
  const serial = db.nextSerial();
  const days = rec.entity_type === "agent" ? AGENT_DAYS : NODE_DAYS;
  const cert = ca.issueCert(caPriv, CA_NID, nid, rec.pub_key,
    rec.capabilities, rec.scope, days, serial, rec.metadata);
  db.insert({ nid, entity_type: rec.entity_type, serial, pub_key: rec.pub_key,
    capabilities: rec.capabilities, scope: rec.scope,
    issued_by: CA_NID, issued_at: cert.issued_at, expires_at: cert.expires_at,
    metadata: rec.metadata });
  return reply.send({ nid, serial, issued_at: cert.issued_at,
    expires_at: cert.expires_at, ident_frame: cert });
});

app.post<{ Params: { nid: string } }>("/v1/agents/:nid/revoke", async (req, reply) => {
  if (!isAuthorized(req)) return unauthorizedReply(reply);
  const nid = req.params.nid;
  const body = req.body as any;
  const reason = body?.reason ?? "cessation_of_operation";
  if (!VALID_REVOKE_REASONS.has(reason))
    return reply.code(400).send({ error_code: "NIP-CA-BAD-REQUEST",
      message: `Invalid revocation reason. Allowed: ${[...VALID_REVOKE_REASONS].join(", ")}` });
  if (!db.revoke(nid, reason))
    return reply.code(404).send({ error_code: "NIP-CA-NID-NOT-FOUND",
      message: `${nid} not found or already revoked` });
  return reply.send({ nid, revoked_at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    reason });
});

app.get<{ Params: { nid: string } }>("/v1/agents/:nid/verify", async (req, reply) => {
  const nid = req.params.nid;
  const rec = db.getActive(nid);
  if (!rec) return reply.code(404).send({ error_code: "NIP-CA-NID-NOT-FOUND", message: `${nid} not found` });
  const valid = new Date(rec.expires_at).getTime() > Date.now();
  return reply.send({ valid, nid, entity_type: rec.entity_type, pub_key: rec.pub_key,
    capabilities: rec.capabilities, issued_by: rec.issued_by,
    issued_at: rec.issued_at, expires_at: rec.expires_at, serial: rec.serial,
    error_code: valid ? null : "NIP-CERT-EXPIRED" });
});

// ── Node lifecycle ────────────────────────────────────────────────────────────
app.post<{ Params: { nid: string } }>("/v1/nodes/:nid/renew", async (req, reply) => {
  if (!isAuthorized(req)) return unauthorizedReply(reply);
  const nid = req.params.nid;
  const rec = db.getActive(nid);
  if (!rec) return reply.code(404).send({ error_code: "NIP-CA-NID-NOT-FOUND", message: `${nid} not found` });
  const expMs = new Date(rec.expires_at).getTime();
  const daysLeft = Math.floor((expMs - Date.now()) / 86400_000);
  if (daysLeft > RENEWAL_DAYS)
    return reply.code(400).send({ error_code: "NIP-CA-RENEWAL-TOO-EARLY",
      message: `Renewal window opens in ${daysLeft - RENEWAL_DAYS} days` });
  const serial = db.nextSerial();
  const days = rec.entity_type === "agent" ? AGENT_DAYS : NODE_DAYS;
  const cert = ca.issueCert(caPriv, CA_NID, nid, rec.pub_key,
    rec.capabilities, rec.scope, days, serial, rec.metadata);
  db.insert({ nid, entity_type: rec.entity_type, serial, pub_key: rec.pub_key,
    capabilities: rec.capabilities, scope: rec.scope,
    issued_by: CA_NID, issued_at: cert.issued_at, expires_at: cert.expires_at,
    metadata: rec.metadata });
  return reply.send({ nid, serial, issued_at: cert.issued_at,
    expires_at: cert.expires_at, ident_frame: cert });
});

app.post<{ Params: { nid: string } }>("/v1/nodes/:nid/revoke", async (req, reply) => {
  if (!isAuthorized(req)) return unauthorizedReply(reply);
  const nid = req.params.nid;
  const body = req.body as any;
  const reason = body?.reason ?? "cessation_of_operation";
  if (!VALID_REVOKE_REASONS.has(reason))
    return reply.code(400).send({ error_code: "NIP-CA-BAD-REQUEST",
      message: `Invalid revocation reason. Allowed: ${[...VALID_REVOKE_REASONS].join(", ")}` });
  if (!db.revoke(nid, reason))
    return reply.code(404).send({ error_code: "NIP-CA-NID-NOT-FOUND",
      message: `${nid} not found or already revoked` });
  return reply.send({ nid, revoked_at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    reason });
});

app.get<{ Params: { nid: string } }>("/v1/nodes/:nid/verify", async (req, reply) => {
  const nid = req.params.nid;
  const rec = db.getActive(nid);
  if (!rec) return reply.code(404).send({ error_code: "NIP-CA-NID-NOT-FOUND", message: `${nid} not found` });
  const valid = new Date(rec.expires_at).getTime() > Date.now();
  return reply.send({ valid, nid, entity_type: rec.entity_type, pub_key: rec.pub_key,
    capabilities: rec.capabilities, issued_by: rec.issued_by,
    issued_at: rec.issued_at, expires_at: rec.expires_at, serial: rec.serial,
    error_code: valid ? null : "NIP-CERT-EXPIRED" });
});

// ── CA info ───────────────────────────────────────────────────────────────────
app.get("/v1/ca/cert", async (_req, reply) =>
  reply.send({ nid: CA_NID, display_name: DISPLAY_NAME, pub_key: caPubStr, algorithm: "ed25519" }));

app.get("/v1/crl", async (_req, reply) =>
  reply.send({ revoked: db.crl() }));

app.get("/.well-known/nps-ca", async (_req, reply) =>
  reply.send({
    nps_ca: "0.2", issuer: CA_NID, display_name: DISPLAY_NAME, public_key: caPubStr,
    algorithms: ["ed25519"],
    cert_formats: ["v1-proprietary", "v2-x509"],   // NPS-RFC-0002 §4.5
    endpoints: {
      register:      `${CA_BASE_URL}/v1/agents/register`,
      register_x509: `${CA_BASE_URL}/v1/agents/register-x509`,   // NPS-RFC-0002
      verify:        `${CA_BASE_URL}/v1/agents/{nid}/verify`,
      ocsp:          `${CA_BASE_URL}/v1/agents/{nid}/verify`,
      crl:           `${CA_BASE_URL}/v1/crl`,
    },
    capabilities: ["agent", "node"],
    max_cert_validity_days: Math.max(AGENT_DAYS, NODE_DAYS),
  }));

app.get("/health", async (_req, reply) => reply.send({ status: "ok" }));

app.listen({ port: PORT, host: "0.0.0.0" }, (err) => {
  if (err) { console.error(err); process.exit(1); }
  console.log(`NIP CA Server listening on :${PORT}`);
});
