package eu.europa.ec.dgc.validation.service;

import eu.europa.ec.dgc.validation.exception.DccException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import org.springframework.stereotype.Service;

@Service
public class DccSign {
    public final static String SIG_ALG = "SHA256withECDSA";

    public String signDcc(String dcc, PrivateKey privateKey) {
        try {
            Signature signature = Signature.getInstance(SIG_ALG);
            signature.initSign(privateKey);
            signature.update(dcc.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(signature.sign());
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new DccException("can not sign dcc",e);
        }
    }

    public boolean verifySignature(String dcc, String dccSignatureBase64, PublicKey publicKey) {
        try {
            Signature signature = Signature.getInstance(SIG_ALG);
            signature.initVerify(publicKey);
            signature.update(dcc.getBytes(StandardCharsets.UTF_8));
            return signature.verify(Base64.getDecoder().decode(dccSignatureBase64));
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new DccException("can not sign dcc",e);
        }
    }

}
