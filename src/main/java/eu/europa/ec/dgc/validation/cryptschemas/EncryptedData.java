package eu.europa.ec.dgc.validation.cryptschemas;

import lombok.Data;

@Data
public class EncryptedData {
    private byte[] dataEncrypted;
    private byte[] encKey;
}
