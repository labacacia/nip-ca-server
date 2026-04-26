// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package com.labacacia.nipcaserver;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKeyFactory;
import java.io.IOException;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
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
