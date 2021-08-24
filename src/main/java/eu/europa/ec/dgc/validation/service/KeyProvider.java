package eu.europa.ec.dgc.validation.service;

import eu.europa.ec.dgc.validation.entity.KeyType;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class KeyProvider {
    private final Map<KeyType,KeyPair> keys = new HashMap<>();

    @PostConstruct
    public void createKeys() throws NoSuchAlgorithmException {
        // TODO generate in memory keys - need persistent key (keystore file)
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
        keyPairGen.initialize(256);
        keys.put(KeyType.ValidationServiceEncKey,keyPairGen.generateKeyPair());
        keys.put(KeyType.ValidationServiceSignKey,keyPairGen.generateKeyPair());
    }

    PublicKey receivePublicKey(KeyType keyType) {
        return keys.get(keyType).getPublic();
    }
    PrivateKey receivePrivateKey(KeyType keyType) {
        return keys.get(keyType).getPrivate();
    }
}
