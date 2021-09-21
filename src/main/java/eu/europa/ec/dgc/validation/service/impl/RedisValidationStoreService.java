package eu.europa.ec.dgc.validation.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.ec.dgc.validation.entity.ValidationInquiry;
import eu.europa.ec.dgc.validation.exception.DccException;
import eu.europa.ec.dgc.validation.service.KeyProvider;
import eu.europa.ec.dgc.validation.service.ValidationStoreService;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

@Service
@Profile("redis")
@RequiredArgsConstructor
public class RedisValidationStoreService implements ValidationStoreService {
    private final StringRedisTemplate stringRedisTemplate;
    private final ObjectMapper objectMapper;
    private final KeyProvider keyProvider;
    private static final String KEY_PREFIX = "sub:";

    public static final int AES_KEY_SIZE = 128;
    public static final int GCM_IV_LENGTH = 12;
    public static final int GCM_TAG_LENGTH = 16;
    public static final String AES_CHIPPER = "AES/GCM/NoPadding";

    @Override
    public void storeValidation(ValidationInquiry validationInquiry) {
        try {
            long timeNow = Instant.now().getEpochSecond();
            stringRedisTemplate.opsForValue().set(KEY_PREFIX + validationInquiry.getSubject(),
                    encryptPayload(validationInquiry),
                    Duration.ofSeconds(validationInquiry.getExp() - timeNow));
        } catch (JsonProcessingException | NoSuchPaddingException
                | NoSuchAlgorithmException | InvalidAlgorithmParameterException
                | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new DccException("can not serialize or encrypt ValidationInquiry", e);
        }
    }

    private String encryptPayload(ValidationInquiry validationInquiry) throws
            NoSuchPaddingException, NoSuchAlgorithmException, JsonProcessingException,
            InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        AESSecrets aesSecrets = deriveSecrets(validationInquiry.getSubject(), keyProvider.receivePrivateKey(keyProvider.getActiveSignKey()));
        Cipher cipher = Cipher.getInstance(AES_CHIPPER);
        // Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(aesSecrets.secretKey, "AES");
        // Create GCMParameterSpec
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, aesSecrets.iv);

        // Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
        return Base64.getEncoder().encodeToString(
                cipher.doFinal(
                        objectMapper.writeValueAsString(validationInquiry).getBytes(StandardCharsets.UTF_8)));
    }

    private ValidationInquiry decryptPayload(String subject, String encryptedPayload) throws
            NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException, JsonProcessingException,
            BadPaddingException, IllegalBlockSizeException {

        AESSecrets aesSecrets = deriveSecrets(subject, keyProvider.receivePrivateKey(keyProvider.getActiveSignKey()));
        Cipher cipher = Cipher.getInstance(AES_CHIPPER);
        // Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(aesSecrets.secretKey, "AES");
        // Create GCMParameterSpec
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, aesSecrets.iv);

        // Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
        byte[] decryptedText = cipher.doFinal(Base64.getDecoder().decode(encryptedPayload));

        return objectMapper.readValue(new String(decryptedText), ValidationInquiry.class);
    }


    @Override
    public ValidationInquiry receiveValidation(String subject) {
        String inquiry = stringRedisTemplate.opsForValue().get(KEY_PREFIX + subject);
        ValidationInquiry validationInquiry;
        if (inquiry != null) {
            try {
                validationInquiry = decryptPayload(subject, inquiry);
            } catch (JsonProcessingException | NoSuchPaddingException | NoSuchAlgorithmException
                    | InvalidAlgorithmParameterException | InvalidKeyException
                    | BadPaddingException | IllegalBlockSizeException e) {
                throw new DccException("can not deserialize ValidationInquiry", e);
            }
        } else {
            validationInquiry = null;
        }
        return validationInquiry;
    }

    @Override
    public void updateValidation(ValidationInquiry validationInquiry) {
        try {
            long timeNow = Instant.now().getEpochSecond();
            stringRedisTemplate.opsForValue().setIfAbsent(KEY_PREFIX + validationInquiry.getSubject(),
                    objectMapper.writeValueAsString(validationInquiry),
                    Duration.ofSeconds(validationInquiry.getExp() - timeNow));
        } catch (JsonProcessingException e) {
            throw new DccException("can not serialize ValidationInquiry", e);
        }
    }

    private AESSecrets deriveSecrets(String subject, PrivateKey privateKey) {
        AESSecrets secrets = new AESSecrets();

        Digest digest = new SHA256Digest();
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(digest);
        hkdf.init(new HKDFParameters(subject.getBytes(StandardCharsets.UTF_8), privateKey.getEncoded(), null));

        secrets.iv = new byte[GCM_IV_LENGTH];
        hkdf.generateBytes(secrets.iv, 0, GCM_IV_LENGTH);

        secrets.secretKey = new byte[AES_KEY_SIZE / 8];
        hkdf.generateBytes(secrets.secretKey, 0, AES_KEY_SIZE / 8);

        return secrets;
    }

    private static class AESSecrets {
        byte[] secretKey;
        byte[] iv;
    }
}
