# Copyright 2026 INNO LOTUS PTY LTD
# SPDX-License-Identifier: Apache-2.0
"""NIP CA Server — Python / FastAPI."""
from __future__ import annotations

import os
import re
import secrets
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Path
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

import ca as ca_module
from db import CaDb

# ── Config ────────────────────────────────────────────────────────────────────

CA_NID           = os.environ["NIP_CA_NID"]
CA_PASSPHRASE    = os.environ["NIP_CA_PASSPHRASE"]
CA_BASE_URL      = os.environ["NIP_CA_BASE_URL"].rstrip("/")
KEY_FILE         = os.environ.get("NIP_CA_KEY_FILE",       "/data/ca.key.enc")
DB_PATH          = os.environ.get("NIP_CA_DB_PATH",        "/data/ca.db")
DISPLAY_NAME     = os.environ.get("NIP_CA_DISPLAY_NAME",   "NPS CA")
AGENT_DAYS       = int(os.environ.get("NIP_CA_AGENT_VALIDITY_DAYS", "30"))
NODE_DAYS        = int(os.environ.get("NIP_CA_NODE_VALIDITY_DAYS",  "90"))
RENEWAL_DAYS     = int(os.environ.get("NIP_CA_RENEWAL_WINDOW_DAYS", "7"))
ROOT_CERT_FILE   = os.environ.get("NIP_CA_ROOT_CERT_FILE", "/data/ca.root.der")
OPERATOR_API_KEY = os.environ.get("NIP_CA_OPERATOR_API_KEY")

_ca_nid_domain = CA_NID.split(":")[-2] if CA_NID.count(":") >= 4 else "ca.local"

_VALID_REVOKE_REASONS = frozenset([
    "key_compromise", "ca_compromise", "affiliation_changed",
    "superseded", "cessation_of_operation",
])
_IDENTIFIER_RE = re.compile(r'^[a-zA-Z0-9._:@/\-]{1,256}$')

# ── Startup ───────────────────────────────────────────────────────────────────

app = FastAPI(title="NIP CA Server", version="0.2.0")
db: CaDb
ca_priv: Any
ca_pub_str: str
ca_root_cert: Any  # x509.Certificate


@app.on_event("startup")
def startup() -> None:
    global db, ca_priv, ca_pub_str, ca_root_cert
    db = CaDb(DB_PATH)
    if not os.path.exists(KEY_FILE):
        ca_priv = ca_module.Ed25519PrivateKey.generate()
        ca_module.save_key(ca_priv, KEY_FILE, CA_PASSPHRASE)
    else:
        ca_priv = ca_module.load_key(KEY_FILE, CA_PASSPHRASE)
    ca_pub_str = ca_module.pub_key_string(ca_priv.public_key())
    # NPS-RFC-0002 — load or generate the X.509 root cert (5-year self-signed).
    ca_root_cert = ca_module.load_or_create_root_cert(ca_priv, CA_NID, ROOT_CERT_FILE)


# ── Auth ──────────────────────────────────────────────────────────────────────

def _require_operator_auth(authorization: str | None = Header(default=None)) -> None:
    if not OPERATOR_API_KEY:
        return
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, {"error_code": "NIP-CA-UNAUTHORIZED",
                                   "message": "Valid operator Bearer token required."})
    provided = authorization[len("Bearer "):]
    if not secrets.compare_digest(provided.encode(), OPERATOR_API_KEY.encode()):
        raise HTTPException(401, {"error_code": "NIP-CA-UNAUTHORIZED",
                                   "message": "Valid operator Bearer token required."})


# ── Request / Response models ─────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    nid: str | None = None
    pub_key: str
    capabilities: list[str] = []
    scope: dict = Field(default_factory=dict)
    metadata: dict | None = None
    # NPS-RFC-0003 — optional, only honoured by register-x509 paths.
    assurance_level: str | None = None


class RevokeRequest(BaseModel):
    reason: str = "cessation_of_operation"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _validate_register(req: RegisterRequest) -> None:
    if not req.pub_key or not req.pub_key.startswith("ed25519:") or len(req.pub_key) <= 8:
        raise HTTPException(400, {"error_code": "NIP-CA-BAD-REQUEST",
                                   "message": "pub_key must be 'ed25519:<base64url>'."})
    if req.nid and not _IDENTIFIER_RE.match(req.nid):
        raise HTTPException(400, {"error_code": "NIP-CA-BAD-REQUEST",
                                   "message": "nid contains invalid characters."})


def _register(req: RegisterRequest, entity_type: str, validity_days: int) -> JSONResponse:
    _validate_register(req)
    nid = req.nid or ca_module.generate_nid(_ca_nid_domain, entity_type)
    if db.get_active(nid):
        raise HTTPException(409, {"error_code": "NIP-CA-NID-ALREADY-EXISTS",
                                   "message": f"{nid} already has an active certificate"})
    serial = db.next_serial()
    cert = ca_module.issue_cert(
        ca_priv, CA_NID, nid, req.pub_key, entity_type,
        req.capabilities, req.scope, validity_days, serial, req.metadata,
    )
    db.insert({"nid": nid, "entity_type": entity_type, "serial": serial,
               "pub_key": req.pub_key, "capabilities": req.capabilities,
               "scope": req.scope, "issued_by": CA_NID,
               "issued_at": cert["issued_at"], "expires_at": cert["expires_at"],
               "metadata": req.metadata})
    return JSONResponse({"nid": nid, "serial": serial,
                          "issued_at": cert["issued_at"], "expires_at": cert["expires_at"],
                          "ident_frame": cert}, status_code=201)


def _register_x509(req: RegisterRequest, entity_type: str, validity_days: int) -> JSONResponse:
    _validate_register(req)
    nid = req.nid or ca_module.generate_nid(_ca_nid_domain, entity_type)
    if db.get_active(nid):
        raise HTTPException(409, {"error_code": "NIP-CA-NID-ALREADY-EXISTS",
                                   "message": f"{nid} already has an active certificate"})
    serial = db.next_serial()
    cert = ca_module.issue_cert_x509(
        ca_priv, CA_NID, ca_root_cert, nid, req.pub_key, entity_type,
        req.capabilities, req.scope, validity_days, serial, req.metadata,
    )
    db.insert({"nid": nid, "entity_type": entity_type, "serial": serial,
               "pub_key": req.pub_key, "capabilities": req.capabilities,
               "scope": req.scope, "issued_by": CA_NID,
               "issued_at": cert["issued_at"], "expires_at": cert["expires_at"],
               "metadata": req.metadata})
    return JSONResponse({"nid": nid, "serial": serial,
                          "issued_at": cert["issued_at"], "expires_at": cert["expires_at"],
                          "ident_frame": cert}, status_code=201)


def _renew(nid: str) -> JSONResponse:
    rec = db.get_active(nid)
    if not rec:
        raise HTTPException(404, {"error_code": "NIP-CA-NID-NOT-FOUND",
                                   "message": f"{nid} not found"})
    expires = datetime.fromisoformat(rec.expires_at.replace("Z", "+00:00"))
    now = datetime.now(timezone.utc)
    days_left = (expires - now).days
    if days_left > RENEWAL_DAYS:
        raise HTTPException(400, {"error_code": "NIP-CA-RENEWAL-TOO-EARLY",
                                   "message": f"Renewal window opens in {days_left - RENEWAL_DAYS} days"})
    validity = AGENT_DAYS if rec.entity_type == "agent" else NODE_DAYS
    serial = db.next_serial()
    cert = ca_module.issue_cert(
        ca_priv, CA_NID, nid, rec.pub_key, rec.entity_type,
        rec.capabilities, rec.scope, validity, serial, rec.metadata,
    )
    db.insert({"nid": nid, "entity_type": rec.entity_type, "serial": serial,
               "pub_key": rec.pub_key, "capabilities": rec.capabilities,
               "scope": rec.scope, "issued_by": CA_NID,
               "issued_at": cert["issued_at"], "expires_at": cert["expires_at"],
               "metadata": rec.metadata})
    return JSONResponse({"nid": nid, "serial": serial,
                          "issued_at": cert["issued_at"], "expires_at": cert["expires_at"],
                          "ident_frame": cert})


def _revoke(nid: str, req: RevokeRequest) -> JSONResponse:
    if req.reason not in _VALID_REVOKE_REASONS:
        raise HTTPException(400, {"error_code": "NIP-CA-BAD-REQUEST",
                                   "message": f"Invalid revocation reason. Allowed: {', '.join(sorted(_VALID_REVOKE_REASONS))}"})
    if not db.revoke(nid, req.reason):
        raise HTTPException(404, {"error_code": "NIP-CA-NID-NOT-FOUND",
                                   "message": f"{nid} not found or already revoked"})
    return JSONResponse({"nid": nid,
                          "revoked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                          "reason": req.reason})


def _verify(nid: str) -> JSONResponse:
    rec = db.get_active(nid)
    if not rec:
        raise HTTPException(404, {"error_code": "NIP-CA-NID-NOT-FOUND",
                                   "message": f"{nid} not found"})
    now = datetime.now(timezone.utc)
    expires = datetime.fromisoformat(rec.expires_at.replace("Z", "+00:00"))
    valid = expires > now
    resp: dict = {
        "valid": valid,
        "nid": nid,
        "entity_type": rec.entity_type,
        "pub_key": rec.pub_key,
        "capabilities": rec.capabilities,
        "issued_by": rec.issued_by,
        "issued_at": rec.issued_at,
        "expires_at": rec.expires_at,
        "serial": rec.serial,
    }
    if not valid:
        resp["error_code"] = "NIP-CERT-EXPIRED"
    return JSONResponse(resp)


# ── Routes ────────────────────────────────────────────────────────────────────

_auth = [Depends(_require_operator_auth)]


@app.post("/v1/agents/register", status_code=201, dependencies=_auth)
def register_agent(req: RegisterRequest) -> JSONResponse:
    return _register(req, "agent", AGENT_DAYS)


@app.post("/v1/nodes/register", status_code=201, dependencies=_auth)
def register_node(req: RegisterRequest) -> JSONResponse:
    return _register(req, "node", NODE_DAYS)


# ── register-x509 (NPS-RFC-0002 X.509 + Ed25519 dual-trust) ──────────────────

@app.post("/v1/agents/register-x509", status_code=201, dependencies=_auth)
def register_agent_x509(req: RegisterRequest) -> JSONResponse:
    return _register_x509(req, "agent", AGENT_DAYS)


@app.post("/v1/nodes/register-x509", status_code=201, dependencies=_auth)
def register_node_x509(req: RegisterRequest) -> JSONResponse:
    return _register_x509(req, "node", NODE_DAYS)


# ── Agent lifecycle ───────────────────────────────────────────────────────────

@app.post("/v1/agents/{nid:path}/renew", dependencies=_auth)
def renew_agent(nid: str = Path(...)) -> JSONResponse:
    return _renew(nid)


@app.post("/v1/agents/{nid:path}/revoke", dependencies=_auth)
def revoke_agent(req: RevokeRequest, nid: str = Path(...)) -> JSONResponse:
    return _revoke(nid, req)


@app.get("/v1/agents/{nid:path}/verify")
def verify_agent(nid: str = Path(...)) -> JSONResponse:
    return _verify(nid)


# ── Node lifecycle ────────────────────────────────────────────────────────────

@app.post("/v1/nodes/{nid:path}/renew", dependencies=_auth)
def renew_node(nid: str = Path(...)) -> JSONResponse:
    return _renew(nid)


@app.post("/v1/nodes/{nid:path}/revoke", dependencies=_auth)
def revoke_node(req: RevokeRequest, nid: str = Path(...)) -> JSONResponse:
    return _revoke(nid, req)


@app.get("/v1/nodes/{nid:path}/verify")
def verify_node(nid: str = Path(...)) -> JSONResponse:
    return _verify(nid)


# ── CA info ───────────────────────────────────────────────────────────────────

@app.get("/v1/ca/cert")
def ca_cert() -> JSONResponse:
    return JSONResponse({
        "nid": CA_NID,
        "display_name": DISPLAY_NAME,
        "pub_key": ca_pub_str,
        "algorithm": "ed25519",
    })


@app.get("/v1/crl")
def crl() -> JSONResponse:
    return JSONResponse({"revoked": db.crl()})


@app.get("/.well-known/nps-ca")
def well_known() -> JSONResponse:
    return JSONResponse({
        "nps_ca": "0.2",
        "issuer": CA_NID,
        "display_name": DISPLAY_NAME,
        "public_key": ca_pub_str,
        "algorithms": ["ed25519"],
        "cert_formats": ["v1-proprietary", "v2-x509"],   # NPS-RFC-0002 §4.5
        "endpoints": {
            "register":      f"{CA_BASE_URL}/v1/agents/register",
            "register_x509": f"{CA_BASE_URL}/v1/agents/register-x509",   # NPS-RFC-0002
            "verify":        f"{CA_BASE_URL}/v1/agents/{{nid}}/verify",
            "ocsp":          f"{CA_BASE_URL}/v1/agents/{{nid}}/verify",
            "crl":           f"{CA_BASE_URL}/v1/crl",
        },
        "capabilities": ["agent", "node"],
        "max_cert_validity_days": max(AGENT_DAYS, NODE_DAYS),
    })


@app.get("/health")
def health() -> JSONResponse:
    return JSONResponse({"status": "ok"})
