package eu.europa.ec.dgc.validation;

import eu.europa.ec.dgc.validation.service.ValidationServiceTest;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

public class AesTest {
    public static final int AES_KEY_SIZE = 128;
    public static final int GCM_IV_LENGTH = 12;
    public static final int GCM_TAG_LENGTH = 16;
    public static final String AES_CHIPPER = "AES/GCM/NoPadding";

    @Test
    void testAas() throws Exception {
        String subject = "764472ab-6896-4b36-8359-29201318a47a";
        PrivateKey privateKey = ValidationServiceTest.parsePrivateKey(ValidationServiceTest.EC_PRIVATE_KEY);

        AESSecrets secrets = deriveSecrets(subject, privateKey);

        String plainText = "DCCTest";

        System.out.println("Original Text : " + plainText);

        byte[] cipherText = encrypt(plainText.getBytes(), secrets);
        System.out.println("Encrypted Text : " + Base64.getEncoder().encodeToString(cipherText));

        secrets = deriveSecrets(subject, privateKey);
        String decryptedText = decrypt(cipherText, secrets);
        System.out.println("DeCrypted Text : " + decryptedText);
        assertEquals(plainText, decryptedText);

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
        keyPairGen.initialize(256);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        AESSecrets secretsWrong = deriveSecrets(subject, keyPair.getPrivate());
        try {
            String decryptedTextWrong = decrypt(cipherText, secretsWrong);
            fail("expect exception here");
        } catch (GeneralSecurityException exception) {

        }
    }

    private AESSecrets deriveSecrets(String subject, PrivateKey privateKey) throws NoSuchAlgorithmException {
        AESSecrets secrets = new AESSecrets();

        Digest digest = new SHA256Digest();
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(digest);
        hkdf.init(new HKDFParameters(subject.getBytes(StandardCharsets.UTF_8), privateKey.getEncoded(), null));

        secrets.iv = new byte[GCM_IV_LENGTH];
        hkdf.generateBytes(secrets.iv, 0, GCM_IV_LENGTH);

        secrets.secretKey = new byte[AES_KEY_SIZE / 8];
        hkdf.generateBytes(secrets.secretKey, 0, AES_KEY_SIZE / 8);

        return secrets;
    }

    public static byte[] encrypt(byte[] plaintext, AESSecrets secrets) throws Exception {
        // Get Cipher Instance
        Cipher cipher = Cipher.getInstance(AES_CHIPPER);

        // Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(secrets.secretKey, "AES");

        // Create GCMParameterSpec
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, secrets.iv);

        // Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);

        // Perform Encryption
        byte[] cipherText = cipher.doFinal(plaintext);

        return cipherText;
    }

    public static String decrypt(byte[] cipherText, AESSecrets secrets) throws Exception {
        // Get Cipher Instance
        Cipher cipher = Cipher.getInstance(AES_CHIPPER);

        // Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(secrets.secretKey, "AES");

        // Create GCMParameterSpec
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, secrets.iv);

        // Initialize Cipher for DECRYPT_MODE
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);

        // Perform Decryption
        byte[] decryptedText = cipher.doFinal(cipherText);

        return new String(decryptedText);
    }

    private static class AESSecrets {
        byte[] secretKey;
        byte[] iv;
    }
}
