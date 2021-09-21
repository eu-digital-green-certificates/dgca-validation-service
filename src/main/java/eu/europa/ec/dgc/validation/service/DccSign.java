package eu.europa.ec.dgc.validation.service;

import eu.europa.ec.dgc.validation.exception.DccException;
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
    public static final String SIG_ALG = "SHA256withECDSA";

    /**
     * sign dcc.
     * @param data data
     * @param privateKey privateKey
     * @return signature as base64
     */
    public String signDcc(byte[] data, PrivateKey privateKey) {
        try {
            Signature signature = Signature.getInstance(SIG_ALG);
            signature.initSign(privateKey);
            signature.update(data);
            return Base64.getEncoder().encodeToString(signature.sign());
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new DccException("can not sign dcc", e);
        }
    }

    /**
     * verify Signature.
     * @param data data
     * @param sig sig
     * @param publicKey publicKey
     * @return true if ok
     */
    public boolean verifySignature(byte[] data, byte[] sig, PublicKey publicKey) {
        try {
            Signature signature = Signature.getInstance(SIG_ALG);
            signature.initVerify(publicKey);
            signature.update(data);
            return signature.verify(sig);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new DccException("can not sign dcc", e);
        }
    }

}
