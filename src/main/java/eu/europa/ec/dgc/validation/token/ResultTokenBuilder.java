package eu.europa.ec.dgc.validation.token;

import eu.europa.ec.dgc.validation.restapi.dto.ValidationStatusResponse;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

public class ResultTokenBuilder {
    private final JwtBuilder builder;

    public ResultTokenBuilder() {
        builder = Jwts.builder();
        builder.setHeaderParam("typ","JWT");
    }

    public ResultTokenBuilder results(List<ValidationStatusResponse.Result> results) {
        builder.claim("results",results);
        return this;
    }

    public String build(PrivateKey privateKey, String kid) {
        return builder.setHeaderParam("kid",kid)
                .signWith(SignatureAlgorithm.ES256, privateKey)
                .compact();
    }
}
