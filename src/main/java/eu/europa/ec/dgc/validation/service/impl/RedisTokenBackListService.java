package eu.europa.ec.dgc.validation.service.impl;

import eu.europa.ec.dgc.validation.service.TokenBlackListService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;

@Profile("redis")
@Service
@RequiredArgsConstructor
public class RedisTokenBackListService implements TokenBlackListService  {
    private final StringRedisTemplate stringRedisTemplate;
    private static final String KEY_PREFIX = "jti:";

    @Override
    public boolean checkPutBlacklist(String jti, long expire) {
        boolean success;
        String key = KEY_PREFIX+jti;
        String value = stringRedisTemplate.opsForValue().get(key);
        if (value == null) {
            long timeNow = Instant.now().getEpochSecond();
            stringRedisTemplate.opsForValue().set(key,"jti", Duration.ofSeconds(expire-timeNow));
            success = true;
        } else {
            success = false;
        }
        return success;
    }
}
