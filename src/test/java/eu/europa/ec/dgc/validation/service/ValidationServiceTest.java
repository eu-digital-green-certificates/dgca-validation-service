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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.MGF1ParameterSpec;
import java.time.Instant;
import java.util.Base64;
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
class ValidationServiceTest {
    public static final String DCC_CRYPT_ALG = "ECIESwithAES-CBC";
    private final String sigAlg = "SHA256withECDSA";
    public static final String KEY_CIPHER = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    public static final String DATA_CIPHER = "AES/CBC/PKCS5Padding";

    private final String subject = "junit";

    @Autowired
    ValidationService validationService;

    @Autowired
    KeyProvider keyProvider;

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

        String dcc = "dcc";
        encodeDcc(dcc, dccValidationRequest);
        String dccSign = signDcc(dcc,keyPair.getPrivate());
        dccValidationRequest.setSig(dccSign);
        dccValidationRequest.setSigAlg(sigAlg);

        System.out.println(objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(dccValidationRequest));

        String accessToken = createAccessTocken();

        String resultToken = validationService.validate(dccValidationRequest, accessToken);

        Jwt token = Jwts.parser().setSigningKey(keyProvider.receiveCertificate(KeyType.ValidationServiceSignKey).getPublicKey()).parse(resultToken);
        System.out.println(token);

    }

    private String createAccessTocken() {
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

        return accessTokenBuilder.payload(accessTokenPayload).build(null,"kid");
    }

    private String signDcc(String dcc, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(sigAlg);
        signature.initSign(privateKey);
        signature.update(dcc.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    private void encodeDcc(String dcc, DccValidationRequest dccValidationRequest) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        // https://cryptobook.nakov.com/asymmetric-key-ciphers/exercises-ecies-encrypt-decrypt

        byte[] derivation = Hex.decode("202122232425262728292a2b2c2d2e2f");
        byte[] encoding = Hex.decode("303132333435363738393a3b3c3d3e3f");
        byte[] nonce = Hex.decode("000102030405060708090a0b0c0d0e0f");
        IESParameterSpec params = new IESParameterSpec(derivation, encoding, 128, 128, nonce, true);

        // encrypt dcc
        Cipher keyCipher = Cipher.getInstance(DCC_CRYPT_ALG);
        keyCipher.init(Cipher.ENCRYPT_MODE, keyProvider.receiveCertificate(KeyType.ValidationServiceEncKey).getPublicKey(),params);
        byte[] dccBytes = dcc.getBytes(StandardCharsets.UTF_8);
        byte[] encodedBytes = keyCipher.doFinal(dccBytes);
        dccValidationRequest.setDcc(Base64.getEncoder().encodeToString(encodedBytes));
        dccValidationRequest.setEncScheme(DCC_CRYPT_ALG);

        Cipher decryptCipher = Cipher.getInstance(DCC_CRYPT_ALG);
        decryptCipher.init(Cipher.DECRYPT_MODE, keyProvider.receivePrivateKey(KeyType.ValidationServiceEncKey),params);
        byte[] dccBytesDecoded = decryptCipher.doFinal(encodedBytes);
        assertArrayEquals(dccBytes,dccBytesDecoded);

        byte[] data256 = new byte[256/8];
        Random random = new Random();
        random.nextBytes(data256);

        Cipher ecEncrypt = Cipher.getInstance("ECIES");
        ecEncrypt.init(Cipher.ENCRYPT_MODE, keyProvider.receiveCertificate(KeyType.ValidationServiceEncKey).getPublicKey());
        byte[] outData = ecEncrypt.doFinal(data256);

        Cipher ecDecrypt = Cipher.getInstance("ECIES");
        ecDecrypt.init(Cipher.DECRYPT_MODE, keyProvider.receivePrivateKey(KeyType.ValidationServiceEncKey));
        byte[] outDataDecrypt = ecDecrypt.doFinal(outData);
        assertArrayEquals(data256, outDataDecrypt);


    }
}