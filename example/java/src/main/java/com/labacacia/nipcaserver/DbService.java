// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package com.labacacia.nipcaserver;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.*;
import java.sql.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Service
public class DbService {

    private final String dbPath;
    private final ObjectMapper mapper = new ObjectMapper();
    private static final DateTimeFormatter ISO = DateTimeFormatter
        .ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneOffset.UTC);

    public DbService(@Value("${nip.ca.db-path:/data/ca.db}") String dbPath) throws Exception {
        this.dbPath = dbPath;
        Path p = Paths.get(dbPath);
        if (p.getParent() != null) Files.createDirectories(p.getParent());
        init();
    }

    private Connection connect() throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
        conn.createStatement().execute("PRAGMA journal_mode=WAL");
        conn.createStatement().execute("PRAGMA foreign_keys=ON");
        return conn;
    }

    private void init() throws Exception {
        Path schema = Paths.get(DbService.class.getResource("/db/001_init.sql").toURI());
        String sql = Files.readString(schema);
        try (Connection conn = connect(); Statement st = conn.createStatement()) {
            for (String stmt : sql.split(";")) {
                if (!stmt.isBlank()) st.execute(stmt.trim());
            }
        }
    }

    public synchronized String nextSerial() throws SQLException {
        try (Connection conn = connect();
             ResultSet rs = conn.createStatement().executeQuery(
                 "SELECT COALESCE(MAX(CAST(REPLACE(serial,'0x','') AS INTEGER)),0)+1 AS n FROM nip_certificates")) {
            rs.next();
            return String.format("0x%06X", rs.getLong("n"));
        }
    }

    public void insert(Map<String, Object> rec) throws Exception {
        try (Connection conn = connect();
             PreparedStatement ps = conn.prepareStatement(
                 "INSERT INTO nip_certificates (nid,entity_type,serial,pub_key,capabilities,scope_json," +
                 "issued_by,issued_at,expires_at,metadata_json) VALUES (?,?,?,?,?,?,?,?,?,?)")) {
            ps.setString(1,  (String) rec.get("nid"));
            ps.setString(2,  (String) rec.get("entity_type"));
            ps.setString(3,  (String) rec.get("serial"));
            ps.setString(4,  (String) rec.get("pub_key"));
            ps.setString(5,  mapper.writeValueAsString(rec.get("capabilities")));
            ps.setString(6,  mapper.writeValueAsString(rec.get("scope")));
            ps.setString(7,  (String) rec.get("issued_by"));
            ps.setString(8,  (String) rec.get("issued_at"));
            ps.setString(9,  (String) rec.get("expires_at"));
            Object meta = rec.get("metadata");
            ps.setString(10, meta != null ? mapper.writeValueAsString(meta) : null);
            ps.executeUpdate();
        }
    }

    public Optional<CertRecord> getActive(String nid) throws Exception {
        try (Connection conn = connect();
             PreparedStatement ps = conn.prepareStatement(
                 "SELECT * FROM nip_certificates WHERE nid=? AND revoked_at IS NULL " +
                 "ORDER BY issued_at DESC LIMIT 1")) {
            ps.setString(1, nid);
            ResultSet rs = ps.executeQuery();
            return rs.next() ? Optional.of(toRecord(rs)) : Optional.empty();
        }
    }

    public boolean revoke(String nid, String reason) throws SQLException {
        String now = ISO.format(Instant.now());
        try (Connection conn = connect();
             PreparedStatement ps = conn.prepareStatement(
                 "UPDATE nip_certificates SET revoked_at=?,revoke_reason=? WHERE nid=? AND revoked_at IS NULL")) {
            ps.setString(1, now); ps.setString(2, reason); ps.setString(3, nid);
            return ps.executeUpdate() > 0;
        }
    }

    public List<Map<String, Object>> crl() throws SQLException {
        List<Map<String, Object>> out = new ArrayList<>();
        try (Connection conn = connect();
             ResultSet rs = conn.createStatement().executeQuery(
                 "SELECT serial,nid,revoked_at,revoke_reason FROM nip_certificates " +
                 "WHERE revoked_at IS NOT NULL ORDER BY revoked_at DESC")) {
            while (rs.next()) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("serial",        rs.getString("serial"));
                row.put("nid",           rs.getString("nid"));
                row.put("revoked_at",    rs.getString("revoked_at"));
                row.put("revoke_reason", rs.getString("revoke_reason"));
                out.add(row);
            }
        }
        return out;
    }

    private CertRecord toRecord(ResultSet rs) throws Exception {
        CertRecord r = new CertRecord();
        r.id          = rs.getLong("id");
        r.nid         = rs.getString("nid");
        r.entityType  = rs.getString("entity_type");
        r.serial      = rs.getString("serial");
        r.pubKey      = rs.getString("pub_key");
        r.capabilities = mapper.readValue(rs.getString("capabilities"),
            new TypeReference<List<String>>() {});
        r.scope       = mapper.readValue(rs.getString("scope_json"),
            new TypeReference<Map<String, Object>>() {});
        r.issuedBy    = rs.getString("issued_by");
        r.issuedAt    = rs.getString("issued_at");
        r.expiresAt   = rs.getString("expires_at");
        r.revokedAt   = rs.getString("revoked_at");
        r.revokeReason = rs.getString("revoke_reason");
        String metaJson = rs.getString("metadata_json");
        r.metadata    = metaJson != null
            ? mapper.readValue(metaJson, new TypeReference<Map<String, Object>>() {}) : null;
        return r;
    }

    public static class CertRecord {
        public long id;
        public String nid, entityType, serial, pubKey;
        public List<String> capabilities;
        public Map<String, Object> scope;
        public String issuedBy, issuedAt, expiresAt, revokedAt, revokeReason;
        public Map<String, Object> metadata;
    }
}
