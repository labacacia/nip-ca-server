// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
import Database from "better-sqlite3";
import * as fs from "node:fs";
import * as path from "node:path";

const SCHEMA_PATH = path.join(__dirname, "..", "db", "001_init.sql");

export interface CertRecord {
  id: number;
  nid: string;
  entity_type: string;
  serial: string;
  pub_key: string;
  capabilities: string[];
  scope: Record<string, unknown>;
  issued_by: string;
  issued_at: string;
  expires_at: string;
  revoked_at: string | null;
  revoke_reason: string | null;
  metadata: Record<string, unknown> | null;
}

export class CaDb {
  private db: Database.Database;

  constructor(dbPath: string) {
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    this.db = new Database(dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("foreign_keys = ON");
    this.db.exec(fs.readFileSync(SCHEMA_PATH, "utf8"));
  }

  nextSerial(): string {
    const row = this.db
      .prepare(
        "SELECT COALESCE(MAX(CAST(REPLACE(serial,'0x','') AS INTEGER)),0)+1 AS n FROM nip_certificates",
      )
      .get() as { n: number };
    return `0x${row.n.toString(16).toUpperCase().padStart(6, "0")}`;
  }

  insert(rec: {
    nid: string; entity_type: string; serial: string; pub_key: string;
    capabilities: string[]; scope: Record<string, unknown>; issued_by: string;
    issued_at: string; expires_at: string; metadata?: Record<string, unknown> | null;
  }): number {
    const result = this.db.prepare(
      `INSERT INTO nip_certificates
       (nid, entity_type, serial, pub_key, capabilities, scope_json,
        issued_by, issued_at, expires_at, metadata_json)
       VALUES (?,?,?,?,?,?,?,?,?,?)`,
    ).run(
      rec.nid, rec.entity_type, rec.serial, rec.pub_key,
      JSON.stringify(rec.capabilities), JSON.stringify(rec.scope),
      rec.issued_by, rec.issued_at, rec.expires_at,
      rec.metadata ? JSON.stringify(rec.metadata) : null,
    );
    return Number(result.lastInsertRowid);
  }

  getActive(nid: string): CertRecord | null {
    const row = this.db.prepare(
      `SELECT * FROM nip_certificates
       WHERE nid=? AND revoked_at IS NULL
       ORDER BY issued_at DESC LIMIT 1`,
    ).get(nid);
    return row ? this._toRecord(row as any) : null;
  }

  revoke(nid: string, reason: string): boolean {
    const now = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    const r = this.db.prepare(
      "UPDATE nip_certificates SET revoked_at=?, revoke_reason=? WHERE nid=? AND revoked_at IS NULL",
    ).run(now, reason, nid);
    return r.changes > 0;
  }

  crl(): Array<{ serial: string; nid: string; revoked_at: string; revoke_reason: string | null }> {
    return this.db.prepare(
      "SELECT serial, nid, revoked_at, revoke_reason FROM nip_certificates WHERE revoked_at IS NOT NULL ORDER BY revoked_at DESC",
    ).all() as any;
  }

  private _toRecord(row: any): CertRecord {
    return {
      id: row.id,
      nid: row.nid,
      entity_type: row.entity_type,
      serial: row.serial,
      pub_key: row.pub_key,
      capabilities: JSON.parse(row.capabilities),
      scope: JSON.parse(row.scope_json),
      issued_by: row.issued_by,
      issued_at: row.issued_at,
      expires_at: row.expires_at,
      revoked_at: row.revoked_at ?? null,
      revoke_reason: row.revoke_reason ?? null,
      metadata: row.metadata_json ? JSON.parse(row.metadata_json) : null,
    };
  }
}
