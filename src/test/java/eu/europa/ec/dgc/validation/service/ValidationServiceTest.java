package eu.europa.ec.dgc.validation.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.ec.dgc.validation.cryptschemas.EncryptedData;
import eu.europa.ec.dgc.validation.cryptschemas.RsaOaepWithSha256AesCbc;
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
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.*;

import lombok.extern.slf4j.Slf4j;
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
    DccCryptService dccCryptService;

    @Autowired
    DccSign dccSign;

    @Autowired
    ObjectMapper objectMapper;


    @Test
    void validateDcc() throws Exception {
        byte[] iv = new byte[]{0, 0, 1, 5, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
        keyPairGen.initialize(256);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        String kid = "bS8D2/Wz5tY=";
        final String audInit = "http://localhost:8080/initialize/"+subject;
        final String audValidate = "http://localhost:8080/validate/"+subject;

        ValidationInitRequest validationInitRequest = new ValidationInitRequest();
        validationInitRequest.setKeyType("EC");
        validationInitRequest.setPubKey(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        validationInitRequest.setNonce(Base64.getEncoder().encodeToString(iv));
        ValidationInitResponse initResponse = validationService.initValidation(validationInitRequest, subject,null,null);
        
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

        byte[] data = encodeDcc(dcc, dccValidationRequest, iv);
        String dccSign = signDcc(data, keyPair.getPrivate());
        dccValidationRequest.setSig(dccSign);
        dccValidationRequest.setSigAlg(DccSign.SIG_ALG);

        dccValidationRequest.setKid(keyProvider.getKid(keyProvider.getKeyNames(KeyType.ValidationServiceEncKey)[0]));

        System.out.println(objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(dccValidationRequest));

        AccessTokenBuilder accessTokenBuilder = new AccessTokenBuilder();
        AccessTokenPayload accessTokenPayload = createAccessTocken(audValidate);
        String accessTokenValidate = accessTokenBuilder.payload(accessTokenPayload).build(parsePrivateKey(EC_PRIVATE_KEY), kid);

        AccessTokenBuilder accessTokenBuilderInit = new AccessTokenBuilder();
        AccessTokenPayload accessTokenPayloadInit = createAccessTocken(audInit);
        String accessTokenInit = accessTokenBuilderInit.payload(accessTokenPayloadInit).build(parsePrivateKey(EC_PRIVATE_KEY), kid);

        AccessTokenPayload accessTokenValidated = validationService.validateAccessToken(audValidate, subject, "Bearer " + accessTokenValidate);
        assertNotNull("access token validation failed");

        System.out.println("jwt init: " + accessTokenInit);
        System.out.println("jwt validate: " + accessTokenValidate);

        String resultToken = validationService.validate(dccValidationRequest, accessTokenPayload);

        Jwt token = Jwts.parser().setSigningKey(keyProvider.receiveCertificate(keyProvider.getKeyNames(KeyType.ValidationServiceSignKey)[0]).get(0).getPublicKey()).parse(resultToken);
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

    private byte[] encodeDcc(String dcc, DccValidationRequest dccValidationRequest, byte[] iv) {
        EncryptedData encryptedData = dccCryptService.encryptData(dcc.getBytes(StandardCharsets.UTF_8),
                keyProvider.receiveCertificate(keyProvider.getKeyNames(KeyType.All)[0]).get(0).getPublicKey(),
                RsaOaepWithSha256AesCbc.ENC_SCHEMA, iv);
        dccValidationRequest.setDcc(Base64.getEncoder().encodeToString(encryptedData.getDataEncrypted()));
        dccValidationRequest.setEncKey(Base64.getEncoder().encodeToString(encryptedData.getEncKey()));
        dccValidationRequest.setEncScheme(RsaOaepWithSha256AesCbc.ENC_SCHEMA);
        return encryptedData.getDataEncrypted();
    }

    private AccessTokenPayload createAccessTocken(String aud) throws InvalidKeySpecException, NoSuchAlgorithmException {
        AccessTokenPayload accessTokenPayload = new AccessTokenPayload();
        accessTokenPayload.setSub(subject);
        accessTokenPayload.setIss("iss");
        accessTokenPayload.setType(AccessTokenType.Cryptographic.intValue());
        accessTokenPayload.setVersion("1.0");
        accessTokenPayload.setJti(UUID.randomUUID().toString());
        accessTokenPayload.setIat(Instant.now().getEpochSecond());
        accessTokenPayload.setAud(aud);
        accessTokenPayload.setExp(Instant.now().getEpochSecond() + 356 * 24 * 60);

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
        accessTokenConditions.setType(new String[]{"v"});
        accessTokenConditions.setValidationClock("2021-01-29T12:00:00+01:00");
        accessTokenConditions.setValidFrom("2021-01-29T12:00:00+01:00");
        accessTokenConditions.setValidTo("2021-01-30T12:00:00+01:00");

        accessTokenPayload.setConditions(accessTokenConditions);

        return accessTokenPayload;
    }

    private String signDcc(byte[] data, PrivateKey privateKey) {
        return dccSign.signDcc(data, privateKey);
    }



}