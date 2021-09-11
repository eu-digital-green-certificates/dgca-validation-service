package eu.europa.ec.dgc.validation.cryptschemas;

import java.security.*;

public interface CryptSchema {
    EncryptedData encryptData(byte[] data, PublicKey publicKey,byte[] iv);
    byte[] decryptData(EncryptedData encryptedData, PrivateKey privateKey, byte[] iv);
    String getEncSchema();
}
