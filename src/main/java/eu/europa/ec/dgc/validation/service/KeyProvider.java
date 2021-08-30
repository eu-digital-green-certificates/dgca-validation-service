package eu.europa.ec.dgc.validation.service;

import eu.europa.ec.dgc.utils.CertificateUtils;
import eu.europa.ec.dgc.validation.config.DgcConfigProperties;
import eu.europa.ec.dgc.validation.entity.KeyType;
import eu.europa.ec.dgc.validation.exception.DccException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class KeyProvider {
    private final DgcConfigProperties dgcConfigProperties;

    private final Map<KeyType, Certificate> certificates = new HashMap<>();
    private final Map<KeyType, PrivateKey> privateKeys = new HashMap<>();
    private final Map<KeyType, String> kids = new HashMap<>();

    @PostConstruct
    public void createKeys() throws NoSuchAlgorithmException, IOException, CertificateException,
            KeyStoreException, UnrecoverableEntryException {
        final char[] keyStorePassword = dgcConfigProperties.getKeyStorePassword().toCharArray();

        Security.addProvider(new BouncyCastleProvider());
        Security.setProperty("crypto.policy", "unlimited");

        KeyStore keyStore = KeyStore.getInstance("JKS");


        File keyFile = new File(dgcConfigProperties.getKeyStoreFile());
        if (!keyFile.isFile()) {
            log.error("keyfile not found on: {} please adapt the configuration property: issuance.keyStoreFile",
                    keyFile);
            throw new DccException("keyfile not found on: " + keyFile
                    + " please adapt the configuration property: issuance.keyStoreFile");
        }
        CertificateUtils certificateUtils = new CertificateUtils();

        try (InputStream is = new FileInputStream(dgcConfigProperties.getKeyStoreFile())) {
            final char[] privateKeyPassword = dgcConfigProperties.getPrivateKeyPassword().toCharArray();
            keyStore.load(is, privateKeyPassword);
            KeyStore.PasswordProtection keyPassword =
                    new KeyStore.PasswordProtection(keyStorePassword);

            for (KeyType keyType : KeyType.values()) {
                String keyName = keyType.name().toLowerCase();
                KeyStore.PrivateKeyEntry privateKeyEntry =
                        (KeyStore.PrivateKeyEntry) keyStore.getEntry(keyName, keyPassword);
                Certificate cert = keyStore.getCertificate(keyName);
                PrivateKey privateKey = privateKeyEntry.getPrivateKey();
                certificates.put(keyType, cert);
                privateKeys.put(keyType, privateKey);
                kids.put(keyType,certificateUtils.getCertKid((X509Certificate) cert));
            }
        }
    }

    Certificate receiveCertificate(KeyType keyType) {
        return certificates.get(keyType);
    }
    PrivateKey receivePrivateKey(KeyType keyType) {
        return privateKeys.get(keyType);
    }
    String getKid(KeyType keyType) {
        return kids.get(keyType);
    }
}
