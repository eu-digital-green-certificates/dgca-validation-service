package eu.europa.ec.dgc.validation.service;

import java.security.PublicKey;

public interface AccessTokenKeyProvider {
    PublicKey getPublicKey(String kid);
}
