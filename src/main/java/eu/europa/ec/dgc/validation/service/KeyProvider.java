package eu.europa.ec.dgc.validation.service;


import eu.europa.ec.dgc.validation.entity.KeyType;
import eu.europa.ec.dgc.validation.entity.KeyUse;
import java.security.PrivateKey;
import java.security.cert.Certificate;

public interface KeyProvider {
    Certificate receiveCertificate(String keyName);

    PrivateKey receivePrivateKey(String keyName);

    String getKeyName(String kid);

    String[] getKeyNames(KeyType type);

    String getKid(String keyName);

    String getAlg(String keyName);

    String getActiveSignKey();

    KeyUse getKeyUse(String keyName);
}
