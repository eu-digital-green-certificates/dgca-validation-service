package eu.europa.ec.dgc.validation;

import eu.europa.ec.dgc.validation.cryptschemas.EncryptedData;
import eu.europa.ec.dgc.validation.cryptschemas.RsaOaepWithSha256AesCBC;
import eu.europa.ec.dgc.validation.cryptschemas.RsaOaepWithSha256AesGCM;
import eu.europa.ec.dgc.validation.service.DccCryptService;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Random;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class DccEncryptionExampleTest {
    RsaOaepWithSha256AesCBC dccCryptService = new RsaOaepWithSha256AesCBC();
    RsaOaepWithSha256AesGCM dccCryptService2 = new RsaOaepWithSha256AesGCM();
    @Test
    void dccEncryptionCBC() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(3072);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        Random random = new Random();
        byte[] data = new byte[2000];
        random.nextBytes(data);
        byte[] iv = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
        EncryptedData encryptedData = dccCryptService.encryptData(data, keyPair.getPublic(),iv);
        byte[] dataDecrypted = dccCryptService.decryptData(encryptedData, keyPair.getPrivate(),iv);

        assertArrayEquals(data, dataDecrypted);
    }

    @Test
    void dccEncryptionGCM() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(3072);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        Random random = new Random();
        byte[] data = new byte[2000];
        random.nextBytes(data);
        byte[] iv = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
        EncryptedData encryptedData = dccCryptService2.encryptData(data, keyPair.getPublic(),iv);
        byte[] dataDecrypted = dccCryptService2.decryptData(encryptedData, keyPair.getPrivate(),iv);

        assertArrayEquals(data, dataDecrypted);
    }
}
