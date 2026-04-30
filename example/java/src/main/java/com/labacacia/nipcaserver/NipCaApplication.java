// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package com.labacacia.nipcaserver;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.io.File;
import java.security.*;
import java.security.cert.X509Certificate;

@SpringBootApplication
public class NipCaApplication {

    public static void main(String[] args) {
        SpringApplication.run(NipCaApplication.class, args);
    }

    /** Holds the live CA keypair and X.509 root cert so controllers can sign without I/O. */
    @Component
    public static class CaState {
        public KeyPair          keyPair;
        public PrivateKey       privateKey;
        public PublicKey        publicKey;
        public String           pubKeyStr;
        public X509Certificate  rootCert;     // RFC-0002 trust anchor

        @Autowired private CaService ca;

        @Value("${nip.ca.key-file:/data/ca.key.enc}")  private String keyFile;
        @Value("${nip.ca.passphrase}")                  private String passphrase;
        @Value("${nip.ca.nid}")                         private String caNid;
        @Value("${nip.ca.root-cert-file:/data/ca.root.der}") private String rootCertFile;

        @PostConstruct
        public void init() throws Exception {
            KeyPair kp;
            if (new File(keyFile).exists()) {
                kp = ca.loadKeyPair(keyFile, passphrase);
            } else {
                kp = ca.generateKeyPair();
                ca.saveKeyPair(kp, keyFile, passphrase);
            }
            keyPair    = kp;
            privateKey = kp.getPrivate();
            publicKey  = kp.getPublic();
            pubKeyStr  = ca.pubKeyString(kp.getPublic());

            // RFC-0002 §4: load or generate self-signed X.509 root cert.
            rootCert = ca.loadOrCreateRootCert(kp, caNid, rootCertFile);
        }
    }
}
