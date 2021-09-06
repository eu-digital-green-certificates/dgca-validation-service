package eu.europa.ec.dgc.validation;

import eu.europa.ec.dgc.validation.cryptschemas.EncryptedData;
import eu.europa.ec.dgc.validation.cryptschemas.RsaOaepWithSha256Aes;
import eu.europa.ec.dgc.validation.service.DccCryptService;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Random;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class DccEncryptionExampleTest {
    RsaOaepWithSha256Aes dccCryptService = new RsaOaepWithSha256Aes();

    @Test
    void dccEncryption() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(3072);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        Random random = new Random();
        byte[] data = new byte[2000];
        random.nextBytes(data);

        EncryptedData encryptedData = dccCryptService.encryptData(data, keyPair.getPublic());
        byte[] dataDecrypted = dccCryptService.decryptData(encryptedData, keyPair.getPrivate());

        assertArrayEquals(data, dataDecrypted);
    }






}
