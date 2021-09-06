package eu.europa.ec.dgc.validation.service;

import eu.europa.ec.dgc.validation.entity.KeyType;

import java.security.PrivateKey;
import java.security.cert.Certificate;

public interface KeyProvider {
    Certificate receiveCertificate(KeyType keyType);

    PrivateKey receivePrivateKey(KeyType keyType);

    String getKid(KeyType keyType);
}
