package eu.europa.ec.dgc.validation.token;

import eu.europa.ec.dgc.validation.config.DgcConfigProperties;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationStatusResponse;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationStatusResponse.Result.ResultType;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.hibernate.id.GUIDGenerator;

public class ResultTokenBuilder {
    private final JwtBuilder builder;
    private final JwtBuilder builder2;
    public ResultTokenBuilder() {
        builder = Jwts.builder();
        builder2 = Jwts.builder();
        builder.setHeaderParam("typ","JWT");
    }

    public String build(List<ValidationStatusResponse.Result> results, 
                        String subject,
                        String issuer, 
                        PrivateKey privateKey, 
                        String kid) {
      
        boolean nok =results!=null? results.stream().anyMatch(t->t.getResult() == ResultType.NOK):false;
        boolean chk =results!=null? (results.stream().anyMatch(t->t.getResult() == ResultType.CHK) || results.size()==0):true;
       
        String result = chk?"CHK": nok?"NOK":"OK";

        String confirmation =  builder2.setHeaderParam("kid",kid)
                                      .setId(UUID.randomUUID().toString())
                                      .setHeaderParam("alg", "ES256")
                                      .setSubject(subject)
                                      .setIssuedAt(Date.from(Instant.now()))
                                      .signWith(SignatureAlgorithm.ES256, privateKey)
                                      .claim("result",result)
                                      .compact();
       
        return builder.setHeaderParam("kid",kid)
                      .setHeaderParam("alg", "ES256")
                      .setSubject(subject)
                      .setIssuer(issuer)
                      .setIssuedAt(Date.from(Instant.now()))
                      .signWith(SignatureAlgorithm.ES256, privateKey)
                      .claim("confirmation", confirmation)
                      .claim("results", results)
                      .claim("result", result)
                      .compact();
    }
}
