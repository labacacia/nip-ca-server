// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	cryptox509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

const (
	pbkdf2Iters = 600_000
	saltLen     = 16
	nonceLen    = 12
	keyLen      = 32
)

// ── Key Management ────────────────────────────────────────────────────────────

// GenerateKey creates a new random Ed25519 signing key.
func GenerateKey() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

// PubKeyString returns the "ed25519:<hex>" encoded public key.
func PubKeyString(pub ed25519.PublicKey) string {
	return "ed25519:" + hex.EncodeToString(pub)
}

// SaveKey encrypts sk with passphrase (PBKDF2+AES-256-GCM) and writes to path.
func SaveKey(sk ed25519.PrivateKey, path, passphrase string) error {
	salt := make([]byte, saltLen)
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	dk := pbkdf2.Key([]byte(passphrase), salt, pbkdf2Iters, keyLen, sha256.New)
	block, err := aes.NewCipher(dk)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// Ed25519 private key seed = first 32 bytes
	seed := []byte(sk)[:32]
	ct := gcm.Seal(nil, nonce, seed, nil)

	pub := sk.Public().(ed25519.PublicKey)
	envelope := map[string]any{
		"version":    1,
		"algorithm":  "ed25519",
		"pub_key":    PubKeyString(pub),
		"salt":       hex.EncodeToString(salt),
		"nonce":      hex.EncodeToString(nonce),
		"ciphertext": hex.EncodeToString(ct),
	}
	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	return nil
}

// LoadKey decrypts the key file at path using passphrase.
func LoadKey(path, passphrase string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var env map[string]any
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, err
	}
	salt, err := hex.DecodeString(env["salt"].(string))
	if err != nil {
		return nil, err
	}
	nonce, err := hex.DecodeString(env["nonce"].(string))
	if err != nil {
		return nil, err
	}
	ct, err := hex.DecodeString(env["ciphertext"].(string))
	if err != nil {
		return nil, err
	}

	dk := pbkdf2.Key([]byte(passphrase), salt, pbkdf2Iters, keyLen, sha256.New)
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	seed, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("key decryption failed — wrong passphrase?")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// ── Signing ───────────────────────────────────────────────────────────────────

// CanonicalJSON serialises obj with keys sorted alphabetically.
func CanonicalJSON(obj map[string]any) []byte {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	buf := []byte{'{'}
	for i, k := range keys {
		if i > 0 {
			buf = append(buf, ',')
		}
		kBytes, _ := json.Marshal(k)
		vBytes, _ := json.Marshal(obj[k])
		buf = append(buf, kBytes...)
		buf = append(buf, ':')
		buf = append(buf, vBytes...)
	}
	buf = append(buf, '}')
	return buf
}

// SignDict signs the canonical JSON of obj with sk and returns "ed25519:<base64>".
func SignDict(sk ed25519.PrivateKey, obj map[string]any) string {
	msg := CanonicalJSON(obj)
	sig := ed25519.Sign(sk, msg)
	return "ed25519:" + base64.StdEncoding.EncodeToString(sig)
}

// ── Certificate Issuance ──────────────────────────────────────────────────────

// GenerateNID creates a random NID for entity_type under domain.
func GenerateNID(domain, entityType string) string {
	uid := make([]byte, 8)
	_, _ = io.ReadFull(rand.Reader, uid)
	return fmt.Sprintf("urn:nps:%s:%s:%s", entityType, domain, hex.EncodeToString(uid))
}

// IssueCert signs and returns an IdentFrame dict.
func IssueCert(
	sk ed25519.PrivateKey,
	caNID, subjectNID, subjectPubKey string,
	capabilities []string,
	scope map[string]any,
	validityDays int,
	serial string,
	metadata map[string]any,
) map[string]any {
	now := time.Now().UTC()
	exp := now.Add(time.Duration(validityDays) * 24 * time.Hour)
	issuedAt := now.Format(time.RFC3339)
	expiresAt := exp.Format(time.RFC3339)

	if capabilities == nil {
		capabilities = []string{}
	}
	if scope == nil {
		scope = map[string]any{}
	}

	caps := make([]any, len(capabilities))
	for i, c := range capabilities {
		caps[i] = c
	}

	unsigned := map[string]any{
		"capabilities": caps,
		"expires_at":   expiresAt,
		"issued_at":    issuedAt,
		"issued_by":    caNID,
		"nid":          subjectNID,
		"pub_key":      subjectPubKey,
		"scope":        scope,
		"serial":       serial,
	}
	sig := SignDict(sk, unsigned)
	cert := map[string]any{
		"capabilities": caps,
		"expires_at":   expiresAt,
		"issued_at":    issuedAt,
		"issued_by":    caNID,
		"nid":          subjectNID,
		"pub_key":      subjectPubKey,
		"scope":        scope,
		"serial":       serial,
		"signature":    sig,
	}
	if metadata != nil {
		cert["metadata"] = metadata
	}
	return cert
}

// ── NPS-RFC-0002 X.509 issuance ──────────────────────────────────────────────

// Provisional OIDs — replace once IANA PEN is granted (RFC-0002 §10 OQ-2).
var (
	oidEkuAgent         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 65715, 1, 1}
	oidEkuNode          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 65715, 1, 2}
	oidNidAssuranceLvl  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 65715, 2, 1}
	oidExtensionExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
)

// LoadOrCreateRootCert loads a self-signed X.509 root from disk, or creates a
// fresh 5-year root and persists it.
func LoadOrCreateRootCert(sk ed25519.PrivateKey, caNID, rootPath string) (*cryptox509.Certificate, error) {
	if data, err := os.ReadFile(rootPath); err == nil {
		return cryptox509.ParseCertificate(data)
	}
	now := time.Now()
	tmpl := &cryptox509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: caNID},
		Issuer:                pkix.Name{CommonName: caNID},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(5 * 365 * 24 * time.Hour),
		KeyUsage:              cryptox509.KeyUsageCertSign | cryptox509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	pub := sk.Public().(ed25519.PublicKey)
	der, err := cryptox509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, sk)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(rootPath), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(rootPath, der, 0o600); err != nil {
		return nil, err
	}
	return cryptox509.ParseCertificate(der)
}

// IssueCertX509 issues a v2 IdentFrame: v1 Ed25519 signature AND a 2-cert
// X.509 chain (leaf + self-signed root). Non-breaking — v1 verifiers ignore
// cert_format/cert_chain. NPS-RFC-0002 §4.
func IssueCertX509(
	sk ed25519.PrivateKey,
	caNID string,
	caRoot *cryptox509.Certificate,
	subjectNID, subjectPubKey, entityType string,
	capabilities []string,
	scope map[string]any,
	validityDays int,
	serial string,
	metadata map[string]any,
) (map[string]any, error) {
	cert := IssueCert(sk, caNID, subjectNID, subjectPubKey,
		capabilities, scope, validityDays, serial, metadata)

	subjectPub, err := parseEd25519PubKeyString(subjectPubKey)
	if err != nil {
		return nil, fmt.Errorf("subject pub_key: %w", err)
	}
	notBefore, _ := time.Parse(time.RFC3339, cert["issued_at"].(string))
	notAfter, _  := time.Parse(time.RFC3339, cert["expires_at"].(string))
	serialInt, ok := new(big.Int).SetString(serial, 16)
	if !ok {
		serialInt = randomSerial()
	}

	leaf, err := issueX509Leaf(subjectNID, subjectPub, sk, caNID, entityType,
		notBefore, notAfter, serialInt)
	if err != nil {
		return nil, err
	}
	cert["cert_format"] = "v2-x509"
	cert["cert_chain"] = []string{
		base64.RawURLEncoding.EncodeToString(leaf.Raw),
		base64.RawURLEncoding.EncodeToString(caRoot.Raw),
	}
	return cert, nil
}

func issueX509Leaf(
	subjectNID string,
	subjectPub ed25519.PublicKey,
	caPriv ed25519.PrivateKey,
	caNID, entityType string,
	notBefore, notAfter time.Time,
	serial *big.Int,
) (*cryptox509.Certificate, error) {
	ekuOid := oidEkuAgent
	if entityType == "node" {
		ekuOid = oidEkuNode
	}
	ekuValue, err := asn1.Marshal([]asn1.ObjectIdentifier{ekuOid})
	if err != nil {
		return nil, err
	}
	uri, err := url.Parse(subjectNID)
	if err != nil {
		return nil, fmt.Errorf("parse subject NID as URI: %w", err)
	}
	// Anonymous (rank 0) — server side issues at default level.
	assuranceDer := []byte{0x0A, 0x01, 0x00}

	tmpl := &cryptox509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: subjectNID},
		Issuer:                pkix.Name{CommonName: caNID},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              cryptox509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{uri},
		ExtraExtensions: []pkix.Extension{
			{Id: oidExtensionExtKeyUsage, Critical: true, Value: ekuValue},
			{Id: oidNidAssuranceLvl,      Critical: false, Value: assuranceDer},
		},
	}
	parent := &cryptox509.Certificate{Subject: pkix.Name{CommonName: caNID}}
	der, err := cryptox509.CreateCertificate(rand.Reader, tmpl, parent, subjectPub, caPriv)
	if err != nil {
		return nil, err
	}
	return cryptox509.ParseCertificate(der)
}

func parseEd25519PubKeyString(s string) (ed25519.PublicKey, error) {
	const prefix = "ed25519:"
	if len(s) <= len(prefix) || s[:len(prefix)] != prefix {
		return nil, fmt.Errorf("unsupported public key format: %s", s)
	}
	raw, err := hex.DecodeString(s[len(prefix):])
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key wrong size: %d", len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

func randomSerial() *big.Int {
	b := make([]byte, 20)
	_, _ = io.ReadFull(rand.Reader, b)
	n := new(big.Int).SetBytes(b)
	if n.Sign() == 0 {
		n.SetInt64(1)
	}
	return n
}
