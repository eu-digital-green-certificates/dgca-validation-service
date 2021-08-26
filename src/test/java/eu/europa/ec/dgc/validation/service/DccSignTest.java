package eu.europa.ec.dgc.validation.service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DccSignTest {

    @Test
    void signTest() throws Exception {
        DccSign dccSign = new DccSign();

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
        keyPairGen.initialize(256);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        String dcc = "dccContent";
        String dccSignature = dccSign.signDcc(dcc,keyPair.getPrivate());
        assertTrue(dccSign.verifySignature(dcc, dccSignature, keyPair.getPublic()));
    }
}