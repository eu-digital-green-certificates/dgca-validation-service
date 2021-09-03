package eu.europa.ec.dgc.validation.service;

import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * In memory blacklist should be replaced by distributed service (redis) in production
 */
@Service
public class TokenBlackListService {
    private Set<String> blacklist = Collections.synchronizedSet(new HashSet<>());

    /**
     * check and put jti in black list
     * @param jti
     * @return false if already in blacklist
     */
    public boolean checkPutBlacklist(String jti) {
        return blacklist.add(jti);
    }
}
