package eu.europa.ec.dgc.validation.service.impl;

import com.nimbusds.jose.util.ArrayUtils;
import eu.europa.ec.dgc.utils.CertificateUtils;
import eu.europa.ec.dgc.validation.config.DgcConfigProperties;
import eu.europa.ec.dgc.validation.entity.KeyType;
import eu.europa.ec.dgc.validation.entity.KeyUse;
import eu.europa.ec.dgc.validation.exception.DccException;
import eu.europa.ec.dgc.validation.service.KeyProvider;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class KeyStoreKeyProvider implements KeyProvider {
    private final DgcConfigProperties dgcConfigProperties;

    private final Map<String, Certificate[]> certificates = new HashMap<>();
    private final Map<String, PrivateKey> privateKeys = new HashMap<>();
    private final Map<String, String> kids = new HashMap<>();
    private final Map<String, String> algs = new HashMap<>();
    private final Map<String, String> kidToName = new HashMap<>();

    /**
     * create keys.
     * @throws NoSuchAlgorithmException NoSuchAlgorithmException
     * @throws IOException IOException
     * @throws CertificateException CertificateException
     * @throws KeyStoreException KeyStoreException
     * @throws UnrecoverableEntryException UnrecoverableEntryException
     */
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

            for (String alias : getKeyNames(KeyType.All)) {

                KeyStore.Entry entry = keyStore.getEntry(alias, keyPassword);

                if (entry instanceof KeyStore.PrivateKeyEntry) {
                    KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
                    PrivateKey privateKey = privateKeyEntry.getPrivateKey();
                    privateKeys.put(alias, privateKey);
                }

                X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
                if (cert == null) {
                    throw new DccException(String.format("Certificate %s can not be parsed", alias));
                }

                Certificate[] certs = keyStore.getCertificateChain(alias);

                if(certs != null) {
                    certificates.put(alias, certs);
                } else {
                    certificates.put(alias, new Certificate[] { cert });
                }

                String kid = certificateUtils.getCertKid((X509Certificate) cert);
                kids.put(alias, kid);
                kidToName.put(kid, alias);

                if (cert.getSigAlgOID().contains("1.2.840.113549.1.1.1")) {
                    algs.put(alias, "RS256");
                }
                if (cert.getSigAlgOID().contains("1.2.840.113549.1.1.10")) {
                    algs.put(alias, "PS256");
                }
                if (cert.getSigAlgOID().contains("1.2.840.10045.4.3.2")) {
                    algs.put(alias, "ES256");
                }
            }
        }
    }

    @Override
    public Certificate[] receiveCertificate(String keyName) {
        return certificates.get(keyName);
    }

    @Override
    public PrivateKey receivePrivateKey(String keyName) {
        return privateKeys.get(keyName);
    }

    @Override
    public String[] getKeyNames(KeyType type) {
        if (type == KeyType.ValidationServiceEncKey) {
            return dgcConfigProperties.getEncAliases();
        }

        if (type == KeyType.ValidationServiceSignKey) {
            return dgcConfigProperties.getSignAliases();
        }

        return ArrayUtils.concat(dgcConfigProperties.getEncAliases(), dgcConfigProperties.getSignAliases());
    }

    @Override
    public String getKid(String keyName) {
        return kids.get(keyName);
    }

    @Override
    public String getAlg(String keyName) {
        return algs.get(keyName);
    }

    @Override
    public String getActiveSignKey() {
        return dgcConfigProperties.getActiveSignKey();
    }

    @Override
    public String getKeyName(String kid) {
        return kidToName.get(kid);
    }

    @Override
    public KeyUse getKeyUse(String keyName) {
        if (Set.of(dgcConfigProperties.getEncAliases()).contains(keyName)) {
            return KeyUse.enc;
        }
        return KeyUse.sig;
    }
}
