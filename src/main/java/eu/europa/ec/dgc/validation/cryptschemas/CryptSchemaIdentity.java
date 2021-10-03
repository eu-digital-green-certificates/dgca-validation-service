package eu.europa.ec.dgc.validation.cryptschemas;

import java.util.ArrayList;
import java.util.List;

public class CryptSchemaIdentity {

    /**
     * Returns all available Crypto Schemes.
     * @return List of Crypto Schemes.
     */
    public static List<String> getCryptSchemes() {
        ArrayList<String> list = new ArrayList<String>();
        list.add(RsaOaepWithSha256AesCbc.ENC_SCHEMA);  
        list.add(RsaOaepWithSha256AesGcm.ENC_SCHEMA);    
        return list;
    }
}
