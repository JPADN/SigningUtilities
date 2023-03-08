package org.example;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

@Getter
@Setter
@AllArgsConstructor
public class SignerCertKey {
    private X509Certificate x509Certificate;
    private PrivateKey privateKey;
}
