package eu.europa.ec.dgc.validation.service;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.annotation.PostConstruct;
import org.springframework.stereotype.Service;

@Service
public class AccessTokenKeyProvider {
    private PublicKey publicKey;

    @PostConstruct
    public void loadKeys() throws NoSuchAlgorithmException, InvalidKeySpecException {
        // TODO mock access key provider
        byte[] keyBytes = Base64.getDecoder().decode("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIPrtYsW9+Juwp/mt7h8F" +
                "J3LgFRIUl2Vlmcl1DUm5gNHl0LnHIL4Jff6mg6yVhehdQiMvkhUtTvmFIUWONSJEnw==");
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("EC");
        publicKey = kf.generatePublic(spec);
    }

    public PublicKey getPublicKey(String kid, String id) {
        return publicKey;
    }
}
