package eu.europa.ec.dgc.validation.cryptschemas;

import eu.europa.ec.dgc.validation.exception.DccException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
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

public class RsaOaepWithSha256AesCbc implements CryptSchema {
    public static final String KEY_CIPHER = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    public static final String DATA_CIPHER = "AES/CBC/PKCS5Padding";
    public static final String ENC_SCHEMA = "RSAOAEPWithSHA256AESCBC";

    /**
     * encrypt data.
     * @param data data
     * @param publicKey publicKey
     * @param iv initialization vector
     * @return encrypted data
     */
    public EncryptedData encryptData(byte[] data, PublicKey publicKey, byte[] iv) {
        try {

            if (iv == null) {
                iv = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            } else if (iv.length > 16 || iv.length < 16 || iv.length % 8 > 0) {
                throw new InvalidKeySpecException();
            }

            EncryptedData encryptedData = new EncryptedData();

            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256); // for example
            SecretKey secretKey = keyGen.generateKey();

            IvParameterSpec ivspec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance(DATA_CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
            encryptedData.setDataEncrypted(cipher.doFinal(data));

            // encrypt RSA key
            Cipher keyCipher = Cipher.getInstance(KEY_CIPHER);
            OAEPParameterSpec oaepParameterSpec = new OAEPParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT
            );
            keyCipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParameterSpec);
            byte[] secretKeyBytes = secretKey.getEncoded();
            encryptedData.setEncKey(keyCipher.doFinal(secretKeyBytes));

            return encryptedData;
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException
            | InvalidKeyException | InvalidAlgorithmParameterException | InvalidKeySpecException e) {
            throw new DccException("encryption error", e);
        }
    }

    /**
     * decrypt data.
     * @param encryptedData encryptedData
     * @param privateKey privateKey
     * @param iv initialization vector
     * @return decrypted data
     */
    public byte[] decryptData(EncryptedData encryptedData, PrivateKey privateKey, byte[] iv) {
        try {

            if (iv == null) {
                iv = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            } else if (iv.length > 16 || iv.length < 16 || iv.length % 8 > 0) {
                throw new InvalidKeySpecException();
            }

            Cipher keyCipher = Cipher.getInstance(KEY_CIPHER);
            OAEPParameterSpec oaepParameterSpec = new OAEPParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT
            );
            keyCipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParameterSpec);
            byte[] rsaKey = keyCipher.doFinal(encryptedData.getEncKey());

            IvParameterSpec ivspec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance(DATA_CIPHER);
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("AES");
            SecretKeySpec secretKeySpec = new SecretKeySpec(rsaKey, 0, rsaKey.length, "AES");
            SecretKey secretKey = secretKeyFactory.generateSecret(secretKeySpec);

            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
            return cipher.doFinal(encryptedData.getDataEncrypted());
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException
            | InvalidKeyException | InvalidAlgorithmParameterException | InvalidKeySpecException e) {
            throw new DccException("encryption error", e);
        }
    }

    public String getEncSchema() {
        return ENC_SCHEMA;
    }

}
