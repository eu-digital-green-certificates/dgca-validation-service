package eu.europa.ec.dgc.validation.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.ec.dgc.validation.entity.KeyType;
import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenConditions;
import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenPayload;
import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenType;
import eu.europa.ec.dgc.validation.restapi.dto.DccValidationRequest;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationInitRequest;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationInitResponse;
import eu.europa.ec.dgc.validation.token.AccessTokenBuilder;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@Slf4j
public class ValidationServiceTest {

    public final static String EC_PRIVATE_KEY = "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCBSuPIbykwH24sjQsT" +
            "neeN6EyjiA1NK5W7uca+HxmGmWw==";
    public final static String EC_PUBLIC_KEY = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIPrtYsW9+Juwp/mt7h8FJ3LgFRIU" +
            "l2Vlmcl1DUm5gNHl0LnHIL4Jff6mg6yVhehdQiMvkhUtTvmFIUWONSJEnw==";

    private final String subject = "junit";

    @Autowired
    ValidationService validationService;

    @Autowired
    KeyProvider keyProvider;

    @Autowired
    DccCrypt dccCrypt;

    @Autowired
    DccSign dccSign;

    AccessTokenBuilder accessTokenBuilder = new AccessTokenBuilder();

    @Test
    void validateDcc() throws Exception {
        ObjectMapper objectMapper =  new ObjectMapper();

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
        keyPairGen.initialize(256);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        ValidationInitRequest validationInitRequest = new ValidationInitRequest();
        validationInitRequest.setKeyType("EC");
        validationInitRequest.setSubject(subject);
        validationInitRequest.setPubKey(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));

        ValidationInitResponse initResponse = validationService.initValidation(validationInitRequest);

        DccValidationRequest dccValidationRequest = new DccValidationRequest();

        String dcc = "HC1:6BFOXN%TSMAHN-H/P8JU6+BS.5E9%UD82.7JJ59W2TT+FM*4/IQ0YVKQCPTHCV4*XUA2PWKP/HLIJL8JF8J" +
                "F7LPMIH-O92UQ7QQ%NH0LA5O6/UIGSU7QQ7NGWWBA 7.UIAYU3X3SH90THYZQ H9+W3.G8MSGPRAAUICO1DV59UE6Q1M650 LHZA0" +
                "D9E2LBHHGKLO-K%FGLIA5D8MJKQJK JMDJL9GG.IA.C8KRDL4O54O4IGUJKJGI.IAHLCV5GVWN.FKP123NJ%HBX/KR968X2-36/-K" +
                "KTCY73$80PU6QW6H+932QDONAC5287T:7N95*K64POPGI*%DC*G2KV SU1Y6B.QEN7+SQ4:4P2C:8UFOFC072.T2PE0*J65UY.2ED" +
                "TYJDK8W$WKF.VUV9L+VF3TY71NSFIM2F:47*J0JLV50M1WB*C";
        encodeDcc(dcc, dccValidationRequest);
        String dccSign = signDcc(dcc,keyPair.getPrivate());
        dccValidationRequest.setSig(dccSign);
        dccValidationRequest.setSigAlg(DccSign.SIG_ALG);

        System.out.println(objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(dccValidationRequest));

        String accessToken = createAccessTocken();

        String resultToken = validationService.validate(dccValidationRequest, accessToken);

        Jwt token = Jwts.parser().setSigningKey(keyProvider.receiveCertificate(KeyType.ValidationServiceSignKey).getPublicKey()).parse(resultToken);
        System.out.println(token);

    }

    static public PublicKey parsePublicKey(String publicKeyBase64) throws InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] keyBytes = Base64.getDecoder().decode(publicKeyBase64);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePublic(spec);
    }

    static public PrivateKey parsePrivateKey(String privateKeyBase64) throws InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] keyBytes = Base64.getDecoder().decode(privateKeyBase64);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePrivate(spec);
    }


    private void encodeDcc(String dcc, DccValidationRequest dccValidationRequest) {
        DccCrypt.EncryptedData enryptedData = dccCrypt.encryptData(dcc.getBytes(StandardCharsets.UTF_8),
                keyProvider.receiveCertificate(KeyType.ValidationServiceEncKey).getPublicKey());
        dccValidationRequest.setDcc(Base64.getEncoder().encodeToString(enryptedData.getDataEncrypted()));
        dccValidationRequest.setEncKey(Base64.getEncoder().encodeToString(enryptedData.getEncKey()));
        dccValidationRequest.setEncScheme(dccCrypt.getEncSchema());
    }

    private String createAccessTocken() throws InvalidKeySpecException, NoSuchAlgorithmException {
        AccessTokenPayload accessTokenPayload = new AccessTokenPayload();
        accessTokenPayload.setSub(subject);
        accessTokenPayload.setIss("iss");
        accessTokenPayload.setType(AccessTokenType.Cryptographic.intValue());
        accessTokenPayload.setVersion("1.0");
        accessTokenPayload.setJti("jti");
        accessTokenPayload.setIat(Instant.now().getEpochSecond());
        accessTokenPayload.setExp(Instant.now().getEpochSecond()+60*60);

        AccessTokenConditions accessTokenConditions = new AccessTokenConditions();
        accessTokenConditions.setHash("hash");
        accessTokenConditions.setLang("en-en");
        accessTokenConditions.setFnt("FNT");
        accessTokenConditions.setGnt("GNT");
        accessTokenConditions.setDob("12-12-2021");
        accessTokenConditions.setCoa("NL");
        accessTokenConditions.setCod("DE");
        accessTokenConditions.setRoa("AW");
        accessTokenConditions.setRod("BW");
        accessTokenConditions.setType(new String[] {"v"});
        accessTokenConditions.setValidationClock("2021-01-29T12:00:00+01:00");
        accessTokenConditions.setValidFrom("2021-01-29T12:00:00+01:00");
        accessTokenConditions.setValidTo("2021-01-30T12:00:00+01:00");

        accessTokenPayload.setConditions(accessTokenConditions);

        return accessTokenBuilder.payload(accessTokenPayload).build(parsePrivateKey(EC_PRIVATE_KEY),"kid");
    }

    private String signDcc(String dcc, PrivateKey privateKey)  {
        return dccSign.signDcc(dcc, privateKey);
    }

}