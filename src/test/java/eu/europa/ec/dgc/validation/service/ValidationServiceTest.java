package eu.europa.ec.dgc.validation.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.ec.dgc.validation.entity.KeyType;
import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenConditions;
import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenPayload;
import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenType;
import eu.europa.ec.dgc.validation.restapi.dto.DccValidationRequest;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationDevRequest;
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

    @Autowired
    ObjectMapper objectMapper;

    AccessTokenBuilder accessTokenBuilder = new AccessTokenBuilder();

    @Test
    void validateDcc() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
        keyPairGen.initialize(256);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        ValidationInitRequest validationInitRequest = new ValidationInitRequest();
        validationInitRequest.setKeyType("EC");
        validationInitRequest.setSubject(subject);
        validationInitRequest.setPubKey(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));

        ValidationInitResponse initResponse = validationService.initValidation(validationInitRequest);
        assertNotNull(initResponse);
        System.out.println("init request");
        System.out.println(objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(validationInitRequest));
        System.out.println("init response");
        System.out.println(objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(initResponse));


        DccValidationRequest dccValidationRequest = new DccValidationRequest();

        String dcc = "HC1:NCF970%90T9WTWGVLK879%EHLE7A1KW8HX*4.AB3XK3F3D86*743F3ZU5.FK1JC X8Y50.FK6ZK7:EDOLFVC*70B$D%" +
                " D3IA4W5646646/96OA76KCN9E%961A69L6QW6B46XJCCWENF6OF63W5NW6-96WJCT3E6N8WJC0FD4:473DSDDF+AKG7RCBA69" +
                "C6A41AZM8JNA5N8LN9VY91OASTA.H9MB8I6A946.JCP9EJY8L/5M/5546.96D46%JCKQE:+9 8D3KC.SC4KCD3DX47B46IL6646" +
                "I*6..DX%DLPCG/D$2DMIALY8/B9ZJC3/DIUADLFE4F-PDI3D7WERB8YTAUIAI3D1 C5LE6%E$PC5$CUZCY$5Y$5JPCT3E5JDOA7" +
                "3467463W5WA6:68 GTFHDZUTOZLO2FL7OU9AQUOAR0NXHY78%$8L65Q93Z81AA60$DUF6XF4EJVUXG4UTN*2YG51UM/.2PGO8P" +
                "I*GS8%LXKBJW8:G6O5";
        encodeDcc(dcc, dccValidationRequest);
        String dccSign = signDcc(dcc,keyPair.getPrivate());
        dccValidationRequest.setSig(dccSign);
        dccValidationRequest.setSigAlg(DccSign.SIG_ALG);
        dccValidationRequest.setKid(keyProvider.getKid(KeyType.ValidationServiceEncKey));

        System.out.println(objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(dccValidationRequest));

        AccessTokenPayload accessTokenPayload = createAccessTocken();
        String accessToken = accessTokenBuilder.payload(accessTokenPayload).build(parsePrivateKey(EC_PRIVATE_KEY),"kid");

        System.out.println("access Token: "+accessToken);

        String resultToken = validationService.validate(dccValidationRequest, accessToken);

        Jwt token = Jwts.parser().setSigningKey(keyProvider.receiveCertificate(KeyType.ValidationServiceSignKey).getPublicKey()).parse(resultToken);
        System.out.println(token);

        ValidationDevRequest validationDevRequest = new ValidationDevRequest();
        validationDevRequest.setDcc(dcc);
        validationDevRequest.setAccessTokenPayload(accessTokenPayload);
        System.out.println(objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(validationDevRequest));

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

    private AccessTokenPayload createAccessTocken() throws InvalidKeySpecException, NoSuchAlgorithmException {
        AccessTokenPayload accessTokenPayload = new AccessTokenPayload();
        accessTokenPayload.setSub(subject);
        accessTokenPayload.setIss("iss");
        accessTokenPayload.setType(AccessTokenType.Cryptographic.intValue());
        accessTokenPayload.setVersion("1.0");
        accessTokenPayload.setJti("jti");
        accessTokenPayload.setIat(Instant.now().getEpochSecond());
        accessTokenPayload.setExp(Instant.now().getEpochSecond()+356*24*60);

        AccessTokenConditions accessTokenConditions = new AccessTokenConditions();
        accessTokenConditions.setHash("hash");
        accessTokenConditions.setLang("en-en");
        accessTokenConditions.setFnt("TRZEWIK");
        accessTokenConditions.setGnt("ARTUR");
        accessTokenConditions.setDob("1990-01-01");
        accessTokenConditions.setCoa("NL");
        accessTokenConditions.setCod("DE");
        accessTokenConditions.setRoa("AW");
        accessTokenConditions.setRod("BW");
        accessTokenConditions.setType(new String[] {"v"});
        accessTokenConditions.setValidationClock("2021-01-29T12:00:00+01:00");
        accessTokenConditions.setValidFrom("2021-01-29T12:00:00+01:00");
        accessTokenConditions.setValidTo("2021-01-30T12:00:00+01:00");

        accessTokenPayload.setConditions(accessTokenConditions);

        return accessTokenPayload;
    }

    private String signDcc(String dcc, PrivateKey privateKey)  {
        return dccSign.signDcc(dcc, privateKey);
    }

}