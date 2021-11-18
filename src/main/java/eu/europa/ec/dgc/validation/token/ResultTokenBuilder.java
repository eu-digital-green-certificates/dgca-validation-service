package eu.europa.ec.dgc.validation.token;

import eu.europa.ec.dgc.validation.restapi.dto.ResultTypeIdentifier;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationStatusResponse;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationStatusResponse.Result.ResultType;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

public class ResultTokenBuilder {
    private final JwtBuilder builder;
    private final JwtBuilder builder2;

    /**
     * constructor.
     */
    public ResultTokenBuilder() {
        builder = Jwts.builder();
        builder2 = Jwts.builder();
        builder.setHeaderParam("typ", "JWT");
    }

    /**
     * evaluate Result.
     * @param results results
     * @return resulting string symbol
     */
    public static String evaluateResult(List<ValidationStatusResponse.Result> results) {
        boolean nok = results != null ? results.stream().anyMatch(t -> t.getResult() == ResultType.NOK
            && t.getType() == ResultTypeIdentifier.TechnicalVerification
            || (t.getType() == ResultTypeIdentifier.IssuerInvalidation && t.getResult() == ResultType.NOK)) : false;
        boolean chk = results != null ? (results.stream().anyMatch(t -> t.getResult() == ResultType.CHK
            || (t.getResult() == ResultType.NOK
                && t.getType() != ResultTypeIdentifier.TechnicalVerification)
        ) || results.size() == 0) : true;

        String result = nok ? "NOK" : chk ? "CHK" : "OK";
        return result;
    }

    /**
     * build the thing.
     * @param results results
     * @param subject subject
     * @param issuer issuer
     * @param privateKey privateKey
     * @param kid kid
     * @return jwt token
     */
    public String build(List<ValidationStatusResponse.Result> results,
                        String subject,
                        String issuer,
                        String[] category,
                        Date expiration,
                        PrivateKey privateKey,
                        String kid,
                        boolean privacy) {

        String result = evaluateResult(results);

        List<ValidationStatusResponse.Result> badResults = results
            .stream()
            .filter(r -> r.getResult() != ResultType.OK)
            .collect(Collectors.toList());


        String confirmation = builder2.setHeaderParam("kid", kid)
            .setId(UUID.randomUUID().toString())
            .setHeaderParam("alg", "ES256")
            .setSubject(subject)
            .setIssuer(issuer)
            .setIssuedAt(Date.from(Instant.now()))
            .setExpiration(expiration)
            .signWith(SignatureAlgorithm.ES256, privateKey)
            .claim("result", result)
            .claim("category",category)
            .compact();

        return builder.setHeaderParam("kid", kid)
            .setHeaderParam("alg", "ES256")
            .setSubject(subject)
            .setIssuer(issuer)
            .setIssuedAt(Date.from(Instant.now()))
            .setExpiration(expiration)
            .signWith(SignatureAlgorithm.ES256, privateKey)
            .claim("category",category)
            .claim("confirmation", confirmation)
            .claim("results", privacy ? new ArrayList<ValidationStatusResponse.Result>() : badResults)
            .claim("result", result)
            .compact();
    }
}
