package eu.europa.ec.dgc.validation.cryptschemas;

import java.security.*;

public interface CryptSchema {
    EncryptedData encryptData(byte[] data, PublicKey publicKey);
    byte[] decryptData(EncryptedData encryptedData, PrivateKey privateKey);
    String getEncSchema();
}
