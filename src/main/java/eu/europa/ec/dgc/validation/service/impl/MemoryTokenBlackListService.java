package eu.europa.ec.dgc.validation.service.impl;

import eu.europa.ec.dgc.validation.service.TokenBlackListService;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * In memory blacklist should be replaced by distributed service (redis) in production
 */
@Service
@Profile("!redis")
public class MemoryTokenBlackListService implements TokenBlackListService {
    private Set<String> blacklist = Collections.synchronizedSet(new HashSet<>());

    /**
     * check and put jti in black list
     * @param jti
     * @return false if already in blacklist
     */
    @Override
    public boolean checkPutBlacklist(String jti, long expire) {
        return blacklist.add(jti);
    }
}
