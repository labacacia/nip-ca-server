// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package com.labacacia.nipcaserver;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

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

    private static final DateTimeFormatter ISO =
        DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneOffset.UTC);

    // ── Register ──────────────────────────────────────────────────────────────

    @PostMapping("/v1/agents/register")
    public ResponseEntity<Map<String, Object>> registerAgent(@RequestBody Map<String, Object> body)
            throws Exception {
        return doRegister(body, "agent", agentDays);
    }

    @PostMapping("/v1/nodes/register")
    public ResponseEntity<Map<String, Object>> registerNode(@RequestBody Map<String, Object> body)
            throws Exception {
        return doRegister(body, "node", nodeDays);
    }

    @SuppressWarnings("unchecked")
    private ResponseEntity<Map<String, Object>> doRegister(
            Map<String, Object> body, String entityType, int days) throws Exception {
        String domain = caNid.contains(":") ? caNid.split(":")[caNid.split(":").length - 2] : "ca.local";
        String nid = body.containsKey("nid") ? (String) body.get("nid")
            : ca.generateNid(domain, entityType);

        if (db.getActive(nid).isPresent())
            return conflict("NIP-CA-NID-ALREADY-EXISTS", nid + " already has an active certificate");

        String pubKey       = (String) body.get("pub_key");
        List<String> caps   = body.containsKey("capabilities")
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

    // ── Renew ─────────────────────────────────────────────────────────────────

    @PostMapping("/v1/agents/{nid}/renew")
    public ResponseEntity<Map<String, Object>> renew(@PathVariable String nid) throws Exception {
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
    public ResponseEntity<Map<String, Object>> revoke(
            @PathVariable String nid, @RequestBody Map<String, Object> body) throws Exception {
        String reason = body.containsKey("reason") ? (String) body.get("reason") : "cessation_of_operation";
        if (!db.revoke(nid, reason))
            return notFound(nid);
        return ResponseEntity.ok(Map.of("nid", nid,
            "revoked_at", ISO.format(Instant.now()), "reason", reason));
    }

    // ── Verify ────────────────────────────────────────────────────────────────

    @GetMapping("/v1/agents/{nid}/verify")
    public ResponseEntity<Map<String, Object>> verify(@PathVariable String nid) throws Exception {
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
        return Map.of(
            "nps_ca", "0.1", "issuer", caNid, "display_name", displayName,
            "public_key", state.pubKeyStr, "algorithms", List.of("ed25519"),
            "endpoints", Map.of(
                "register", base + "/v1/agents/register",
                "verify",   base + "/v1/agents/{nid}/verify",
                "ocsp",     base + "/v1/agents/{nid}/verify",
                "crl",      base + "/v1/crl"),
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

class Duration {
    static java.time.Duration between(java.time.Instant a, java.time.Instant b) {
        return java.time.Duration.between(a, b);
    }
}
