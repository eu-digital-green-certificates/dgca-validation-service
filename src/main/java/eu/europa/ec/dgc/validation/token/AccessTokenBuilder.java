package eu.europa.ec.dgc.validation.token;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.ec.dgc.validation.exception.DccException;
import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenPayload;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.security.PrivateKey;

/**
 * Builder for AccessToken.
 */
public class AccessTokenBuilder {
    private final JwtBuilder builder;
    private final ObjectMapper objectMapper;

    /**
     * contructor.
     */
    public AccessTokenBuilder() {
        builder = Jwts.builder();
        builder.setHeaderParam("typ", "JWT");
        objectMapper = new ObjectMapper();
    }

    /**
     * set payload.
     * @param accessTokenPayload accessTokenPayload
     * @return self
     */
    public AccessTokenBuilder payload(AccessTokenPayload accessTokenPayload) {
        try {
            builder.setPayload(objectMapper.writeValueAsString(accessTokenPayload));
        } catch (JsonProcessingException e) {
            throw new DccException("can not serialize accessTokenPayload", e);
        }
        return this;
    }

    /**
     * build the token.
     * @param privateKey  privateKey
     * @param kid kid
     * @return jwt string
     */
    public String build(PrivateKey privateKey, String kid) {
        return builder
            .setHeaderParam("kid", kid)
            .signWith(SignatureAlgorithm.ES256, privateKey)
            .compact();
    }
}
