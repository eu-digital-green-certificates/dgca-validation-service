package eu.europa.ec.dgc.validation.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.ec.dgc.validation.entity.ValidationInquiry;
import eu.europa.ec.dgc.validation.exception.DccException;
import eu.europa.ec.dgc.validation.service.ValidationStoreService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;

@Service
@Profile("redis")
@RequiredArgsConstructor
public class RedisValidationStoreService implements ValidationStoreService {
    private final StringRedisTemplate stringRedisTemplate;
    private final ObjectMapper objectMapper;
    private static final String KEY_PREFIX = "sub:";

    @Override
    public void storeValidation(ValidationInquiry validationInquiry) {
        try {
            long timeNow = Instant.now().getEpochSecond();
            stringRedisTemplate.opsForValue().set(KEY_PREFIX+validationInquiry.getSubject(),
                    objectMapper.writeValueAsString(validationInquiry),
                    Duration.ofSeconds(validationInquiry.getExp()-timeNow));
        } catch (JsonProcessingException e) {
            throw new DccException("can not serialize ValidationInquiry",e);
        }
    }

    @Override
    public ValidationInquiry receiveValidation(String subject) {
        String inquiry = stringRedisTemplate.opsForValue().get(KEY_PREFIX+subject);
        ValidationInquiry validationInquiry;
        if (inquiry!=null) {
            try {
                validationInquiry = objectMapper.readValue(inquiry,ValidationInquiry.class);
            } catch (JsonProcessingException e) {
                throw new DccException("can not deserialize ValidationInquiry",e);
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
            stringRedisTemplate.opsForValue().setIfAbsent(KEY_PREFIX+validationInquiry.getSubject(),
                    objectMapper.writeValueAsString(validationInquiry),
                    Duration.ofSeconds(validationInquiry.getExp()-timeNow));
        } catch (JsonProcessingException e) {
            throw new DccException("can not serialize ValidationInquiry",e);
        }
    }
}
