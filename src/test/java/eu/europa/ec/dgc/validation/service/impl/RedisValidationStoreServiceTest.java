package eu.europa.ec.dgc.validation.service.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.ec.dgc.validation.entity.ValidationInquiry;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

@ExtendWith(MockitoExtension.class)
class RedisValidationStoreServiceTest {

    @Mock
    private KeyStoreKeyProvider keyProvider;

    @Mock
    private StringRedisTemplate stringRedisTemplate;

    @Mock
    private ValueOperations<String, String> valueOperations;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private RedisValidationStoreService underTest;

    @Captor
    ArgumentCaptor<String> valueStoredInRedis;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        this.underTest = new RedisValidationStoreService(stringRedisTemplate, objectMapper, keyProvider);
    }

    /**
     * Check that data that is stored in redis encrypted can be retrieved and decrypted with the same subject.
     * @throws NoSuchAlgorithmException if key generation fails
     */
    @Test
    void storeAndRead() throws NoSuchAlgorithmException {
        KeyPair kp = createKeyPair();

        when(stringRedisTemplate.opsForValue()).thenReturn(valueOperations);
        when(keyProvider.getActiveSignKey()).thenReturn("1234");
        when(keyProvider.receivePrivateKey("1234")).thenReturn(kp.getPrivate());
        ValidationInquiry val = createValidationInquiry(ValidationInquiry.ValidationStatus.OPEN, kp);

        underTest.storeValidation(val);

        verify(valueOperations).set(any(), valueStoredInRedis.capture(), any());

        final String encoded = valueStoredInRedis.getValue();

        when(valueOperations.get("sub:" + val.getSubject())).thenReturn(encoded);
        ValidationInquiry fromRedis = underTest.receiveValidation(val.getSubject());
        assertEquals(val.getValidationStatus(), fromRedis.getValidationStatus());
    }

    /**
     * Check that data that is updated with encryption in redis can be retrieved and decrypted with the same subject.
     * @throws NoSuchAlgorithmException if key generation fails
     */
    @Test
    void storeUpdateAndRead() throws NoSuchAlgorithmException {
        KeyPair kp = createKeyPair();

        when(stringRedisTemplate.opsForValue()).thenReturn(valueOperations);
        when(keyProvider.getActiveSignKey()).thenReturn("1234");
        when(keyProvider.receivePrivateKey("1234")).thenReturn(kp.getPrivate());
        ValidationInquiry val = createValidationInquiry(ValidationInquiry.ValidationStatus.OPEN, kp);

        underTest.storeValidation(val);

        verify(valueOperations).set(any(), valueStoredInRedis.capture(), any());
        final String encoded = valueStoredInRedis.getValue();

        when(valueOperations.get("sub:" + val.getSubject())).thenReturn(encoded);
        ValidationInquiry fromRedis = underTest.receiveValidation(val.getSubject());
        assertEquals(val.getValidationStatus(), fromRedis.getValidationStatus());

        val.setValidationStatus(ValidationInquiry.ValidationStatus.READY);
        underTest.updateValidation(val);

        verify(valueOperations).setIfPresent(any(), valueStoredInRedis.capture(), any());

        final String updated = valueStoredInRedis.getValue();
        when(valueOperations.get("sub:" + val.getSubject())).thenReturn(updated);
        ValidationInquiry fromRedisUpdated = underTest.receiveValidation(val.getSubject());
        assertEquals(val.getValidationStatus(), fromRedisUpdated.getValidationStatus());

    }

    private KeyPair createKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        return kpg.generateKeyPair();
    }

    private ValidationInquiry createValidationInquiry(ValidationInquiry.ValidationStatus status,
                                                      KeyPair kp) {
        ValidationInquiry validationInquiry = new ValidationInquiry();
        validationInquiry.setValidationStatus(status);
        validationInquiry.setSubject(UUID.randomUUID().toString());
        validationInquiry.setValidationResult("OK");
        validationInquiry.setExp(1_000_000);
        validationInquiry.setPublicKey(kp.getPublic().toString());
        validationInquiry.setKeyType("RSA");
        return validationInquiry;
    }
}