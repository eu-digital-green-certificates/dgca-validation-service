package eu.europa.ec.dgc.validation.token;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.ec.dgc.validation.exception.DccException;
import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenPayload;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationStatusResponse;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.security.PrivateKey;
import java.util.List;

public class AccessTokenBuilder {
    private final JwtBuilder builder;
    private final ObjectMapper objectMapper;

    public AccessTokenBuilder() {
        builder = Jwts.builder();
        builder.setHeaderParam("typ","JWT");
        objectMapper = new ObjectMapper();
    }

    public AccessTokenBuilder payload(AccessTokenPayload accessTokenPayload) {
        try {
            builder.setPayload(objectMapper.writeValueAsString(accessTokenPayload));
        } catch (JsonProcessingException e) {
            throw new DccException("can not serialize accessTokenPayload",e);
        }
        return this;
    }

    public String build(PrivateKey privateKey, String kid) {
        return builder
                .setHeaderParam("kid",kid)
                .signWith(SignatureAlgorithm.ES256, privateKey)
                .compact();
    }
}
