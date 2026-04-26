// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package com.labacacia.nipcaserver;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.io.File;
import java.security.*;

@SpringBootApplication
public class NipCaApplication {

    public static void main(String[] args) {
        SpringApplication.run(NipCaApplication.class, args);
    }

    /** Holds the live CA keypair so controllers can sign without I/O. */
    @Component
    public static class CaState {
        public PrivateKey privateKey;
        public String     pubKeyStr;

        @Autowired private CaService ca;

        @Value("${nip.ca.key-file:/data/ca.key.enc}") private String keyFile;
        @Value("${nip.ca.passphrase}")                 private String passphrase;
        @Value("${nip.ca.nid}")                        private String caNid;

        @PostConstruct
        public void init() throws Exception {
            KeyPair kp;
            if (new File(keyFile).exists()) {
                kp = ca.loadKeyPair(keyFile, passphrase);
            } else {
                kp = ca.generateKeyPair();
                ca.saveKeyPair(kp, keyFile, passphrase);
            }
            privateKey = kp.getPrivate();
            pubKeyStr  = ca.pubKeyString(kp.getPublic());
        }
    }
}
