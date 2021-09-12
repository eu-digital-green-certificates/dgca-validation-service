package eu.europa.ec.dgc.validation.service;

import eu.europa.ec.dgc.validation.cryptschemas.CryptSchema;
import eu.europa.ec.dgc.validation.cryptschemas.EncryptedData;
import eu.europa.ec.dgc.validation.cryptschemas.RsaOaepWithSha256AesCBC;
import eu.europa.ec.dgc.validation.cryptschemas.RsaOaepWithSha256AesGCM;
import eu.europa.ec.dgc.validation.exception.DccException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.PostConstruct;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import lombok.Data;
import org.springframework.stereotype.Service;

@Service
public class DccCryptService {
    private Map<String, CryptSchema> cryptSchemaMap;

    @PostConstruct
    public void initSchemas() {
        cryptSchemaMap = new HashMap<>();
        CryptSchema cryptSchema = new RsaOaepWithSha256AesCBC();
        CryptSchema cryptSchema2 = new RsaOaepWithSha256AesGCM();
        cryptSchemaMap.put(cryptSchema.getEncSchema(), cryptSchema);
        cryptSchemaMap.put(cryptSchema2.getEncSchema(), cryptSchema2);
    }

    public EncryptedData encryptData(byte[] data, PublicKey publicKey, String encSchema, byte[] iv) {
        CryptSchema cryptSchema = cryptSchemaMap.get(encSchema);
        if (cryptSchema!=null) {
            return cryptSchema.encryptData(data, publicKey,iv);
        } else {
            throw new DccException("encryption schema not supported "+encSchema);
        }
    }

    public byte[] decryptData(EncryptedData encryptedData, PrivateKey privateKey, String encSchema, byte[] iv) {
        CryptSchema cryptSchema = cryptSchemaMap.get(encSchema);
        if (cryptSchema!=null) {
            return cryptSchema.decryptData(encryptedData, privateKey,iv);
        } else {
            throw new DccException("encryption schema not supported "+encSchema);
        }
    }

}
