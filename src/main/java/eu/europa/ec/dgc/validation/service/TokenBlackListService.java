package eu.europa.ec.dgc.validation.service;

public interface TokenBlackListService {
    boolean checkPutBlacklist(String jti);
}
