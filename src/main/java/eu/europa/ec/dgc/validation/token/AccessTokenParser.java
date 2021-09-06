package eu.europa.ec.dgc.validation.token;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.ec.dgc.validation.exception.DccException;
import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenPayload;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import java.security.PublicKey;
import org.springframework.stereotype.Service;

@Service
public class AccessTokenParser {
    private final ObjectMapper objectMapper = new ObjectMapper();

    public AccessTokenPayload parseToken(String jwtCompact, PublicKey publicKey) {
        Jwt token = Jwts.parser().setSigningKey(publicKey).parse(jwtCompact);
        try {
            String payloadJson = objectMapper.writeValueAsString(token.getBody());
            return objectMapper.readValue(payloadJson,AccessTokenPayload.class);
        } catch (JsonProcessingException e) {
            throw new DccException("can not parse access token "+e.getMessage(),e);
        }
    }

    public String extractKid(String jwtCompat) {
        String[] splitToken = jwtCompat.split("\\.");
        String unsignedToken = splitToken[0] + "." + splitToken[1] + ".";
        Jwt token = Jwts.parser().parse(unsignedToken);
        return (String) token.getHeader().get("kid");
    }
}
