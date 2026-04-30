// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package com.labacacia.nipcaserver;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.labacacia.nps.nip.AssuranceLevel;
import com.labacacia.nps.nip.IdentCertFormat;
import com.labacacia.nps.nip.x509.Ed25519PublicKeys;
import com.labacacia.nps.nip.x509.NipX509Builder;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKeyFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Service
public class CaService {

    private static final int PBKDF2_ITERS = 600_000;
    private static final int KEY_LEN      = 32;   // bytes
    private static final int SALT_LEN     = 16;
    private static final int NONCE_LEN    = 12;
    private static final int GCM_TAG_BITS = 128;

    // Ed25519 PKCS8 header — prepend to 32-byte seed to get full private key DER
    private static final byte[] PKCS8_HEADER =
        HexFormat.of().parseHex("302e020100300506032b657004220420");

    private final ObjectMapper mapper = new ObjectMapper()
        .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);

    // ── Key Management ────────────────────────────────────────────────────────

    public KeyPair generateKeyPair() throws GeneralSecurityException {
        return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    /** Returns "ed25519:<hex-of-32-byte-raw-public-key>". */
    public String pubKeyString(PublicKey pub) {
        byte[] der = pub.getEncoded(); // SubjectPublicKeyInfo, last 32 bytes = raw key
        byte[] raw = Arrays.copyOfRange(der, der.length - 32, der.length);
        return "ed25519:" + HexFormat.of().formatHex(raw);
    }

    /** Saves keypair: seed encrypted with AES-256-GCM+PBKDF2. */
    public void saveKeyPair(KeyPair kp, String filePath, String passphrase) throws Exception {
        byte[] salt   = randomBytes(SALT_LEN);
        byte[] nonce  = randomBytes(NONCE_LEN);
        byte[] dk     = pbkdf2(passphrase, salt);
        // Ed25519 PKCS8 DER = 48 bytes; seed = last 32 bytes
        byte[] pkcs8  = kp.getPrivate().getEncoded();
        byte[] seed   = Arrays.copyOfRange(pkcs8, pkcs8.length - 32, pkcs8.length);
        byte[] ciphertext = aesgcmEncrypt(dk, nonce, seed);

        Map<String, Object> env = new LinkedHashMap<>();
        env.put("version",    1);
        env.put("algorithm",  "ed25519");
        env.put("pub_key",    pubKeyString(kp.getPublic()));
        env.put("salt",       HexFormat.of().formatHex(salt));
        env.put("nonce",      HexFormat.of().formatHex(nonce));
        env.put("ciphertext", HexFormat.of().formatHex(ciphertext));

        Path p = Paths.get(filePath);
        if (p.getParent() != null) Files.createDirectories(p.getParent());
        Files.writeString(p, mapper.writeValueAsString(env));
        p.toFile().setReadable(true,  true);  p.toFile().setReadable(false, false);
        p.toFile().setWritable(true,  true);  p.toFile().setWritable(false, false);
    }

    /** Loads keypair from encrypted file. */
    public KeyPair loadKeyPair(String filePath, String passphrase) throws Exception {
        @SuppressWarnings("unchecked")
        Map<String, Object> env = mapper.readValue(Files.readString(Paths.get(filePath)), Map.class);
        byte[] salt       = HexFormat.of().parseHex((String) env.get("salt"));
        byte[] nonce      = HexFormat.of().parseHex((String) env.get("nonce"));
        byte[] ciphertext = HexFormat.of().parseHex((String) env.get("ciphertext"));
        byte[] dk         = pbkdf2(passphrase, salt);
        byte[] seed;
        try {
            seed = aesgcmDecrypt(dk, nonce, ciphertext);
        } catch (Exception e) {
            throw new IllegalStateException("Key decryption failed — wrong passphrase?", e);
        }
        byte[] der = new byte[PKCS8_HEADER.length + seed.length];
        System.arraycopy(PKCS8_HEADER, 0, der, 0, PKCS8_HEADER.length);
        System.arraycopy(seed, 0, der, PKCS8_HEADER.length, seed.length);
        PrivateKey priv = KeyFactory.getInstance("Ed25519")
            .generatePrivate(new PKCS8EncodedKeySpec(der));
        // Derive public key via sign+extract: not available directly in stdlib.
        // Use a workaround: re-derive from PKCS8 by constructing a self-signed temp.
        // Simpler: store pub_key in envelope and restore from hex.
        String pubHex = ((String) env.get("pub_key")).replace("ed25519:", "");
        byte[] rawPub = HexFormat.of().parseHex(pubHex);
        // SubjectPublicKeyInfo for Ed25519 = 12-byte header + 32-byte raw key
        byte[] spkiHeader = HexFormat.of().parseHex("302a300506032b6570032100");
        byte[] spki = new byte[spkiHeader.length + rawPub.length];
        System.arraycopy(spkiHeader, 0, spki, 0, spkiHeader.length);
        System.arraycopy(rawPub, 0, spki, spkiHeader.length, rawPub.length);
        PublicKey pub = KeyFactory.getInstance("Ed25519")
            .generatePublic(new X509EncodedKeySpec(spki));
        return new KeyPair(pub, priv);
    }

    // ── Signing ───────────────────────────────────────────────────────────────

    public String signDict(PrivateKey priv, Map<String, Object> dict) throws Exception {
        byte[] data = mapper.writeValueAsBytes(new TreeMap<>(dict));
        Signature sig = Signature.getInstance("Ed25519");
        sig.initSign(priv);
        sig.update(data);
        return "ed25519:" + Base64.getEncoder().encodeToString(sig.sign());
    }

    // ── Certificate Issuance ──────────────────────────────────────────────────

    public Map<String, Object> issueCert(
            PrivateKey caPriv, String caNid,
            String subjectNid, String subjectPubKey,
            List<String> capabilities, Map<String, Object> scope,
            int validityDays, String serial, Map<String, Object> metadata) throws Exception {
        Instant now     = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        Instant expires = now.plusSeconds((long) validityDays * 86400);
        DateTimeFormatter fmt = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'")
            .withZone(ZoneOffset.UTC);

        Map<String, Object> unsigned = new TreeMap<>();
        unsigned.put("capabilities", capabilities);
        unsigned.put("expires_at",   fmt.format(expires));
        unsigned.put("issued_at",    fmt.format(now));
        unsigned.put("issued_by",    caNid);
        unsigned.put("nid",          subjectNid);
        unsigned.put("pub_key",      subjectPubKey);
        unsigned.put("scope",        scope);
        unsigned.put("serial",       serial);

        Map<String, Object> cert = new LinkedHashMap<>(unsigned);
        cert.put("signature", signDict(caPriv, unsigned));
        if (metadata != null && !metadata.isEmpty()) cert.put("metadata", metadata);
        return cert;
    }

    public String generateNid(String domain, String entityType) {
        byte[] uid = new byte[8];
        new SecureRandom().nextBytes(uid);
        return "urn:nps:" + entityType + ":" + domain + ":" + HexFormat.of().formatHex(uid);
    }

    // ── X.509 issuance (NPS-RFC-0002) ────────────────────────────────────────

    /**
     * Load a self-signed X.509 root cert from {@code rootPath}, or generate one if missing.
     * The root binds the CA's NID and Ed25519 public key; it is used as the trust anchor
     * for v2 IdentFrames.
     */
    public X509Certificate loadOrCreateRootCert(KeyPair caKp, String caNid, String rootPath)
            throws Exception {
        Path p = Paths.get(rootPath);
        if (Files.exists(p)) {
            try (var in = Files.newInputStream(p)) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                return (X509Certificate) cf.generateCertificate(in);
            }
        }
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        X509Certificate root = NipX509Builder.issueRoot(
            caNid, caKp.getPrivate(),
            Ed25519PublicKeys.extractRaw(caKp.getPublic()),
            now.minus(Duration.ofMinutes(1)),
            now.plus(Duration.ofDays(365L * 5)),
            new BigInteger(160, new SecureRandom()));
        if (p.getParent() != null) Files.createDirectories(p.getParent());
        Files.write(p, root.getEncoded());
        return root;
    }

    /**
     * Issue a v2 IdentFrame with both the legacy v1 Ed25519 signature AND an X.509 cert chain.
     * The v1 signature path is unchanged so v1-only verifiers continue to accept the frame
     * (RFC-0002 §8.1 Phase 1 dual-trust).
     */
    public Map<String, Object> issueCertX509(
            KeyPair         caKp,
            String          caNid,
            X509Certificate rootCert,
            String          subjectNid,
            String          subjectPubKey,         // "ed25519:<hex>"
            List<String>    capabilities,
            Map<String, Object> scope,
            int             validityDays,
            String          serial,
            Map<String, Object> metadata,
            AssuranceLevel  assuranceLevel,
            String          entityType) throws Exception {
        // 1) v1 IdentFrame (existing path) — produces the Ed25519 CA signature.
        Map<String, Object> frame = issueCert(caKp.getPrivate(), caNid,
            subjectNid, subjectPubKey, capabilities, scope,
            validityDays, serial, metadata);

        // 2) Build X.509 leaf signed by the same CA key.
        byte[] subjectRaw = HexFormat.of().parseHex(
            subjectPubKey.replace("ed25519:", ""));
        Instant now    = Instant.parse(((String) frame.get("issued_at")));
        Instant expiry = Instant.parse(((String) frame.get("expires_at")));
        BigInteger serialBig = parseSerial(serial);
        NipX509Builder.LeafRole role = "node".equals(entityType)
            ? NipX509Builder.LeafRole.NODE : NipX509Builder.LeafRole.AGENT;

        X509Certificate leaf = NipX509Builder.issueLeaf(
            subjectNid, subjectRaw,
            caKp.getPrivate(), caNid,
            role,
            assuranceLevel == null ? AssuranceLevel.ANONYMOUS : assuranceLevel,
            now, expiry, serialBig);

        // 3) Attach cert_format + cert_chain to the v1 frame (non-breaking).
        Base64.Encoder urlEnc = Base64.getUrlEncoder().withoutPadding();
        List<String> chain = List.of(
            urlEnc.encodeToString(leaf.getEncoded()),
            urlEnc.encodeToString(rootCert.getEncoded()));

        Map<String, Object> v2 = new LinkedHashMap<>(frame);
        v2.put("cert_format", IdentCertFormat.V2_X509);
        v2.put("cert_chain",  chain);
        if (assuranceLevel != null) v2.put("assurance_level", assuranceLevel.wire());
        return v2;
    }

    private static BigInteger parseSerial(String s) {
        // CA serials look like "0xABCD..." — convert to BigInteger.
        if (s == null || s.isBlank()) return new BigInteger(160, new SecureRandom());
        String hex = s.startsWith("0x") || s.startsWith("0X") ? s.substring(2) : s;
        return new BigInteger(hex, 16);
    }

    // ── Internal Crypto ───────────────────────────────────────────────────────

    private byte[] randomBytes(int len) {
        byte[] b = new byte[len]; new SecureRandom().nextBytes(b); return b;
    }

    private byte[] pbkdf2(String passphrase, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(passphrase.toCharArray(), salt, PBKDF2_ITERS, KEY_LEN * 8);
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
    }

    private byte[] aesgcmEncrypt(byte[] key, byte[] nonce, byte[] pt) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, nonce));
        return c.doFinal(pt);
    }

    private byte[] aesgcmDecrypt(byte[] key, byte[] nonce, byte[] ct) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, nonce));
        return c.doFinal(ct);
    }
}
