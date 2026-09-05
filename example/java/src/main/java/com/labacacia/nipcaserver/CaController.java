// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package com.labacacia.nipcaserver;

import com.labacacia.nps.nip.AssuranceLevel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;

@RestController
public class CaController {

    @Autowired private CaService ca;
    @Autowired private DbService db;
    @Autowired private NipCaApplication.CaState state;

    @Value("${nip.ca.nid}")          private String caNid;
    @Value("${nip.ca.base-url}")     private String baseUrl;
    @Value("${nip.ca.display-name:NPS CA}") private String displayName;
    @Value("${nip.ca.agent-validity-days:30}") private int agentDays;
    @Value("${nip.ca.node-validity-days:90}")  private int nodeDays;
    @Value("${nip.ca.renewal-window-days:7}")  private int renewalDays;
    @Value("${nip.ca.operator-api-key:}")      private String operatorApiKey;

    private static final DateTimeFormatter ISO =
        DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneOffset.UTC);

    private static final Set<String> VALID_REASONS = Set.of(
        "key_compromise", "ca_compromise", "affiliation_changed",
        "superseded", "cessation_of_operation");

    // ── Auth ──────────────────────────────────────────────────────────────────

    private boolean isAuthorized(String auth) {
        if (operatorApiKey == null || operatorApiKey.isEmpty()) return true;
        if (auth == null || !auth.startsWith("Bearer ")) return false;
        String provided = auth.substring(7);
        return MessageDigest.isEqual(
            provided.getBytes(StandardCharsets.UTF_8),
            operatorApiKey.getBytes(StandardCharsets.UTF_8));
    }

    private <T> ResponseEntity<T> unauthorized() {
        return ResponseEntity.status(401)
            .body((T) Map.of("error_code", "NIP-CA-UNAUTHORIZED",
                             "message", "Valid operator Bearer token required."));
    }

    private boolean isValidPubKey(String key) {
        return key != null && key.startsWith("ed25519:") && key.length() > 8;
    }

    // ── Register ──────────────────────────────────────────────────────────────

    @PostMapping("/v1/agents/register")
    public ResponseEntity<Map<String, Object>> registerAgent(
            @RequestBody Map<String, Object> body,
            @RequestHeader(value = "Authorization", required = false) String auth) throws Exception {
        if (!isAuthorized(auth)) return unauthorized();
        return doRegister(body, "agent", agentDays);
    }

    @PostMapping("/v1/nodes/register")
    public ResponseEntity<Map<String, Object>> registerNode(
            @RequestBody Map<String, Object> body,
            @RequestHeader(value = "Authorization", required = false) String auth) throws Exception {
        if (!isAuthorized(auth)) return unauthorized();
        return doRegister(body, "node", nodeDays);
    }

    @SuppressWarnings("unchecked")
    private ResponseEntity<Map<String, Object>> doRegister(
            Map<String, Object> body, String entityType, int days) throws Exception {
        String pubKey = (String) body.get("pub_key");
        if (!isValidPubKey(pubKey))
            return ResponseEntity.badRequest().body(Map.of(
                "error_code", "NIP-CA-BAD-REQUEST",
                "message", "pub_key must be 'ed25519:<base64url>'."));

        String domain = caNid.contains(":") ? caNid.split(":")[caNid.split(":").length - 2] : "ca.local";
        String nid = body.containsKey("nid") ? (String) body.get("nid")
            : ca.generateNid(domain, entityType);

        if (db.getActive(nid).isPresent())
            return conflict("NIP-CA-NID-ALREADY-EXISTS", nid + " already has an active certificate");

        List<String> caps = body.containsKey("capabilities")
            ? (List<String>) body.get("capabilities") : List.of();
        Map<String, Object> scope = body.containsKey("scope")
            ? (Map<String, Object>) body.get("scope") : Map.of();
        Map<String, Object> meta = (Map<String, Object>) body.get("metadata");

        String serial = db.nextSerial();
        Map<String, Object> cert = ca.issueCert(state.privateKey, caNid, nid, pubKey,
            caps, scope, days, serial, meta);

        Map<String, Object> rec = new HashMap<>();
        rec.put("nid", nid); rec.put("entity_type", entityType); rec.put("serial", serial);
        rec.put("pub_key", pubKey); rec.put("capabilities", caps); rec.put("scope", scope);
        rec.put("issued_by", caNid); rec.put("issued_at", cert.get("issued_at"));
        rec.put("expires_at", cert.get("expires_at")); rec.put("metadata", meta);
        db.insert(rec);

        return ResponseEntity.status(201).body(Map.of(
            "nid", nid, "serial", serial,
            "issued_at", cert.get("issued_at"), "expires_at", cert.get("expires_at"),
            "ident_frame", cert));
    }

    // ── register-x509 (NPS-RFC-0002 X.509 + Ed25519 dual-trust) ─────────────

    @PostMapping("/v1/agents/register-x509")
    public ResponseEntity<Map<String, Object>> registerAgentX509(
            @RequestBody Map<String, Object> body,
            @RequestHeader(value = "Authorization", required = false) String auth) throws Exception {
        if (!isAuthorized(auth)) return unauthorized();
        return doRegisterX509(body, "agent", agentDays);
    }

    @PostMapping("/v1/nodes/register-x509")
    public ResponseEntity<Map<String, Object>> registerNodeX509(
            @RequestBody Map<String, Object> body,
            @RequestHeader(value = "Authorization", required = false) String auth) throws Exception {
        if (!isAuthorized(auth)) return unauthorized();
        return doRegisterX509(body, "node", nodeDays);
    }

    @SuppressWarnings("unchecked")
    private ResponseEntity<Map<String, Object>> doRegisterX509(
            Map<String, Object> body, String entityType, int days) throws Exception {
        String pubKey = (String) body.get("pub_key");
        if (!isValidPubKey(pubKey))
            return ResponseEntity.badRequest().body(Map.of(
                "error_code", "NIP-CA-BAD-REQUEST",
                "message", "pub_key must be 'ed25519:<base64url>'."));

        String domain = caNid.contains(":") ? caNid.split(":")[caNid.split(":").length - 2] : "ca.local";
        String nid = body.containsKey("nid") ? (String) body.get("nid")
            : ca.generateNid(domain, entityType);

        if (db.getActive(nid).isPresent())
            return conflict("NIP-CA-NID-ALREADY-EXISTS", nid + " already has an active certificate");

        List<String> caps = body.containsKey("capabilities")
            ? (List<String>) body.get("capabilities") : List.of();
        Map<String, Object> scope = body.containsKey("scope")
            ? (Map<String, Object>) body.get("scope") : Map.of();
        Map<String, Object> meta = (Map<String, Object>) body.get("metadata");
        AssuranceLevel level = body.containsKey("assurance_level")
            ? AssuranceLevel.fromWire((String) body.get("assurance_level"))
            : AssuranceLevel.ANONYMOUS;

        String serial = db.nextSerial();
        Map<String, Object> cert = ca.issueCertX509(state.keyPair, caNid, state.rootCert,
            nid, pubKey, caps, scope, days, serial, meta, level, entityType);

        Map<String, Object> rec = new HashMap<>();
        rec.put("nid", nid); rec.put("entity_type", entityType); rec.put("serial", serial);
        rec.put("pub_key", pubKey); rec.put("capabilities", caps); rec.put("scope", scope);
        rec.put("issued_by", caNid); rec.put("issued_at", cert.get("issued_at"));
        rec.put("expires_at", cert.get("expires_at")); rec.put("metadata", meta);
        db.insert(rec);

        return ResponseEntity.status(201).body(Map.of(
            "nid", nid, "serial", serial,
            "issued_at", cert.get("issued_at"), "expires_at", cert.get("expires_at"),
            "ident_frame", cert));
    }

    // ── Renew ─────────────────────────────────────────────────────────────────

    @PostMapping("/v1/agents/{nid}/renew")
    public ResponseEntity<Map<String, Object>> renewAgent(
            @PathVariable String nid,
            @RequestHeader(value = "Authorization", required = false) String auth) throws Exception {
        if (!isAuthorized(auth)) return unauthorized();
        return doRenew(nid);
    }

    @PostMapping("/v1/nodes/{nid}/renew")
    public ResponseEntity<Map<String, Object>> renewNode(
            @PathVariable String nid,
            @RequestHeader(value = "Authorization", required = false) String auth) throws Exception {
        if (!isAuthorized(auth)) return unauthorized();
        return doRenew(nid);
    }

    private ResponseEntity<Map<String, Object>> doRenew(String nid) throws Exception {
        Optional<DbService.CertRecord> opt = db.getActive(nid);
        if (opt.isEmpty()) return notFound(nid);
        DbService.CertRecord rec = opt.get();

        Instant exp = Instant.parse(rec.expiresAt.replace("Z", "") + "Z");
        long daysLeft = Duration.between(Instant.now(), exp).toDays();
        if (daysLeft > renewalDays)
            return ResponseEntity.badRequest().body(Map.of(
                "error_code", "NIP-CA-RENEWAL-TOO-EARLY",
                "message", "Renewal window opens in " + (daysLeft - renewalDays) + " days"));

        int days = "agent".equals(rec.entityType) ? agentDays : nodeDays;
        String serial = db.nextSerial();
        Map<String, Object> cert = ca.issueCert(state.privateKey, caNid, nid, rec.pubKey,
            rec.capabilities, rec.scope, days, serial, rec.metadata);

        Map<String, Object> row = new HashMap<>();
        row.put("nid", nid); row.put("entity_type", rec.entityType); row.put("serial", serial);
        row.put("pub_key", rec.pubKey); row.put("capabilities", rec.capabilities);
        row.put("scope", rec.scope); row.put("issued_by", caNid);
        row.put("issued_at", cert.get("issued_at")); row.put("expires_at", cert.get("expires_at"));
        row.put("metadata", rec.metadata);
        db.insert(row);

        return ResponseEntity.ok(Map.of("nid", nid, "serial", serial,
            "issued_at", cert.get("issued_at"), "expires_at", cert.get("expires_at"),
            "ident_frame", cert));
    }

    // ── Revoke ────────────────────────────────────────────────────────────────

    @PostMapping("/v1/agents/{nid}/revoke")
    public ResponseEntity<Map<String, Object>> revokeAgent(
            @PathVariable String nid,
            @RequestBody Map<String, Object> body,
            @RequestHeader(value = "Authorization", required = false) String auth) throws Exception {
        if (!isAuthorized(auth)) return unauthorized();
        return doRevoke(nid, body);
    }

    @PostMapping("/v1/nodes/{nid}/revoke")
    public ResponseEntity<Map<String, Object>> revokeNode(
            @PathVariable String nid,
            @RequestBody Map<String, Object> body,
            @RequestHeader(value = "Authorization", required = false) String auth) throws Exception {
        if (!isAuthorized(auth)) return unauthorized();
        return doRevoke(nid, body);
    }

    private ResponseEntity<Map<String, Object>> doRevoke(String nid, Map<String, Object> body) throws Exception {
        String reason = body.containsKey("reason") ? (String) body.get("reason") : "cessation_of_operation";
        if (!VALID_REASONS.contains(reason))
            return ResponseEntity.badRequest().body(Map.of(
                "error_code", "NIP-CA-BAD-REQUEST",
                "message", "Invalid revocation reason. Allowed: " + String.join(", ", VALID_REASONS)));
        if (!db.revoke(nid, reason))
            return notFound(nid);
        return ResponseEntity.ok(Map.of("nid", nid,
            "revoked_at", ISO.format(Instant.now()), "reason", reason));
    }

    // ── Verify ────────────────────────────────────────────────────────────────

    @GetMapping("/v1/agents/{nid}/verify")
    public ResponseEntity<Map<String, Object>> verifyAgent(@PathVariable String nid) throws Exception {
        return doVerify(nid);
    }

    @GetMapping("/v1/nodes/{nid}/verify")
    public ResponseEntity<Map<String, Object>> verifyNode(@PathVariable String nid) throws Exception {
        return doVerify(nid);
    }

    private ResponseEntity<Map<String, Object>> doVerify(String nid) throws Exception {
        Optional<DbService.CertRecord> opt = db.getActive(nid);
        if (opt.isEmpty()) return notFound(nid);
        DbService.CertRecord rec = opt.get();
        boolean valid = Instant.parse(rec.expiresAt.replace("Z", "") + "Z").isAfter(Instant.now());
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("valid", valid); resp.put("nid", nid); resp.put("entity_type", rec.entityType);
        resp.put("pub_key", rec.pubKey); resp.put("capabilities", rec.capabilities);
        resp.put("issued_by", rec.issuedBy); resp.put("issued_at", rec.issuedAt);
        resp.put("expires_at", rec.expiresAt); resp.put("serial", rec.serial);
        if (!valid) resp.put("error_code", "NIP-CERT-EXPIRED");
        return ResponseEntity.ok(resp);
    }

    // ── CA Info ───────────────────────────────────────────────────────────────

    @GetMapping("/v1/ca/cert")
    public Map<String, Object> caCert() {
        return Map.of("nid", caNid, "display_name", displayName,
            "pub_key", state.pubKeyStr, "algorithm", "ed25519");
    }

    @GetMapping("/v1/crl")
    public Map<String, Object> crl() throws Exception {
        return Map.of("revoked", db.crl());
    }

    @GetMapping("/.well-known/nps-ca")
    public Map<String, Object> wellKnown() {
        String base = baseUrl.replaceAll("/$", "");
        Map<String, Object> endpoints = new LinkedHashMap<>();
        endpoints.put("register",      base + "/v1/agents/register");
        endpoints.put("register_x509", base + "/v1/agents/register-x509");  // NPS-RFC-0002 X.509 + Ed25519
        endpoints.put("verify",        base + "/v1/agents/{nid}/verify");
        endpoints.put("ocsp",          base + "/v1/agents/{nid}/verify");
        endpoints.put("crl",           base + "/v1/crl");
        return Map.of(
            "nps_ca", "0.2",
            "issuer", caNid, "display_name", displayName,
            "public_key", state.pubKeyStr, "algorithms", List.of("ed25519"),
            "cert_formats", List.of("v1-proprietary", "v2-x509"),  // NPS-RFC-0002 §4.5
            "endpoints", endpoints,
            "capabilities", List.of("agent", "node"),
            "max_cert_validity_days", Math.max(agentDays, nodeDays));
    }

    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "ok");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private <T> ResponseEntity<T> notFound(String nid) {
        return ResponseEntity.status(404)
            .body((T) Map.of("error_code", "NIP-CA-NID-NOT-FOUND", "message", nid + " not found"));
    }

    private <T> ResponseEntity<T> conflict(String code, String msg) {
        return ResponseEntity.status(409).body((T) Map.of("error_code", code, "message", msg));
    }
}
