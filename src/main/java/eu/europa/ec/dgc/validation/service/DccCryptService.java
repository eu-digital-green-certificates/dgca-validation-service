package eu.europa.ec.dgc.validation.service;

import eu.europa.ec.dgc.validation.cryptschemas.CryptSchema;
import eu.europa.ec.dgc.validation.cryptschemas.EncryptedData;
import eu.europa.ec.dgc.validation.cryptschemas.RsaOaepWithSha256AesCbc;
import eu.europa.ec.dgc.validation.cryptschemas.RsaOaepWithSha256AesGcm;
import eu.europa.ec.dgc.validation.exception.DccException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.PostConstruct;
import org.springframework.stereotype.Service;

@Service
public class DccCryptService {
    private Map<String, CryptSchema> cryptSchemaMap;

    /**
     * init schemas.
     */
    @PostConstruct
    public void initSchemas() {
        cryptSchemaMap = new HashMap<>();
        CryptSchema cryptSchema = new RsaOaepWithSha256AesCbc();
        CryptSchema cryptSchema2 = new RsaOaepWithSha256AesGcm();
        cryptSchemaMap.put(cryptSchema.getEncSchema(), cryptSchema);
        cryptSchemaMap.put(cryptSchema2.getEncSchema(), cryptSchema2);
    }

    /**
     * encrypt Data.
     * @param data data
     * @param publicKey publicKey
     * @param encSchema encSchema
     * @param iv iv
     * @return EncryptedData
     */
    public EncryptedData encryptData(byte[] data, PublicKey publicKey, String encSchema, byte[] iv) {
        CryptSchema cryptSchema = cryptSchemaMap.get(encSchema);
        if (cryptSchema != null) {
            return cryptSchema.encryptData(data, publicKey, iv);
        } else {
            throw new DccException("encryption schema not supported " + encSchema);
        }
    }

    /**
     * decrypt Data.
     * @param encryptedData encryptedData
     * @param privateKey privateKey
     * @param encSchema encSchema
     * @param iv iv
     * @return decrypted data
     */
    public byte[] decryptData(EncryptedData encryptedData, PrivateKey privateKey, String encSchema, byte[] iv) {
        CryptSchema cryptSchema = cryptSchemaMap.get(encSchema);
        if (cryptSchema != null) {
            return cryptSchema.decryptData(encryptedData, privateKey, iv);
        } else {
            throw new DccException("encryption schema not supported " + encSchema);
        }
    }

}
