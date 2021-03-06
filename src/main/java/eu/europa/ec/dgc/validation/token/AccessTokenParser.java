package eu.europa.ec.dgc.validation.token;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.ec.dgc.validation.exception.DccException;
import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenPayload;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import java.security.PublicKey;
import org.apache.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
public class AccessTokenParser {
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * parse Token.
     * @param jwtCompact jwtCompact
     * @param publicKey publicKey
     * @return AccessTokenPayload
     */
    public AccessTokenPayload parseToken(String jwtCompact, PublicKey publicKey) {
        Jwt token = Jwts.parser().setSigningKey(publicKey).parse(jwtCompact);
        try {
            String payloadJson = objectMapper.writeValueAsString(token.getBody());
            return objectMapper.readValue(payloadJson, AccessTokenPayload.class);
        } catch (JsonProcessingException e) {
            throw new DccException("can not parse access token " + e.getMessage(), HttpStatus.SC_BAD_REQUEST);
        }
    }

    /**
     * extract payload.
     * @param jwtCompact jwtCompact
     * @return JWT
     */
    public Jwt extractPayload(String jwtCompact) {
        String[] splitToken = jwtCompact.split("\\.");
        String unsignedToken = splitToken[0] + "." + splitToken[1] + ".";
        return Jwts.parser().parse(unsignedToken);
    }
}
