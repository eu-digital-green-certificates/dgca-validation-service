package eu.europa.ec.dgc.validation.cryptschemas;

import java.util.ArrayList;
import java.util.List;

public class CryptSchemaIdentity {
    public static List<String> GetCryptSchemes() {
        ArrayList<String> list = new ArrayList<String>();
        list.add(RsaOaepWithSha256AesCbc.ENC_SCHEMA);  
        list.add(RsaOaepWithSha256AesGcm.ENC_SCHEMA);    
        return list;
    }
}
