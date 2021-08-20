package eu.europa.ec.dgc.validation;

import eu.europa.ec.dgc.validation.restapi.dto.ValidationInitResponse;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationStatusResponse;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import org.junit.jupiter.api.Test;

class JwtTest {
    @Test
    void createResultTokenJwt() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
        keyPairGen.initialize(256);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        List<ValidationStatusResponse.Result> results = new ArrayList<>();
        ValidationStatusResponse.Result result = new ValidationStatusResponse.Result();
        result.setResult(ValidationStatusResponse.Result.ResultType.OK);
        results.add(result);

        String jwtString = Jwts.builder().claim("test","test")
                .setHeaderParam("kid","kid")
                .setHeaderParam("typ","JWT")
                .setIssuedAt(new Date())
                .setIssuer("issuer")
                .setSubject("sub").claim("confirmation","confirmation-jwt")
                .claim("results",results)
                .signWith(SignatureAlgorithm.ES256,keyPair.getPrivate())
                .compact();
        System.out.println(jwtString);

        Jwt token = Jwts.parser().setSigningKey(keyPair.getPublic()).parse(jwtString);
        System.out.println(token);

    }
}
