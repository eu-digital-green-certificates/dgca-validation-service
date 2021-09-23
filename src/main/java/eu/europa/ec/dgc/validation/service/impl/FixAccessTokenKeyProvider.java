package eu.europa.ec.dgc.validation.service.impl;

import eu.europa.ec.dgc.validation.config.DgcConfigProperties;
import eu.europa.ec.dgc.validation.exception.DccException;
import eu.europa.ec.dgc.validation.service.AccessTokenKeyProvider;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
@ConditionalOnProperty(prefix = "dgc", name = "decoratorUrl", matchIfMissing = true, havingValue = "fix")
public class FixAccessTokenKeyProvider implements AccessTokenKeyProvider {
    private final Map<String,PublicKey> publicKeys = new HashMap<>();
    private static final String UNSET_KEYS_VALUE = "overwrite_my_by_env";
    private final DgcConfigProperties dgcConfigProperties;

    /**
     * load Keys.
     * @throws NoSuchAlgorithmException NoSuchAlgorithmException
     * @throws InvalidKeySpecException InvalidKeySpecException
     */
    @PostConstruct
    public void loadKeys() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String keys = dgcConfigProperties.getAccessKeys();
        KeyFactory kf = KeyFactory.getInstance("EC");
        if (UNSET_KEYS_VALUE.equals(keys)) {
            throw new IllegalArgumentException("please set env variable DGC_ACCESSKEYS for access keys "
                + "'kid1:publicKey1:kid2:publicKey2'");
        } else {
            String[] keysSplit = keys.split(":");
            if (keysSplit.length % 2 != 0) {
                throw new IllegalArgumentException("wrong format for access keys env variable: "
                    + "DGC_ACCESSKEYS, expect: 'kid1:publicKey1:kid2:publicKey2'");
            }
            for (int i = 0;i < keysSplit.length;i += 2) {
                String kid = keysSplit[i];
                byte[] keyBytes = Base64.getDecoder().decode(keysSplit[i + 1]);
                X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
                PublicKey publicKey = kf.generatePublic(spec);
                publicKeys.put(kid,publicKey);
                log.info("access key with kid={} was registered",kid);
            }
        }
    }

    @Override
    public PublicKey getPublicKey(String kid) {
        PublicKey publicKey = publicKeys.get(kid);
        if (publicKey == null) {
            throw new DccException("can not find access key with kid: " + kid);
        }
        return publicKey;
    }
}
