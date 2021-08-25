package eu.europa.ec.dgc.validation.token;

import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenConditions;
import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenPayload;
import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenType;
import java.time.Instant;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

class AccessTokenParserTest {
    AccessTokenParser accessTokenParser = new AccessTokenParser();
    AccessTokenBuilder accessTokenBuilder = new AccessTokenBuilder();

    @Test
    void testAccessTokenParser() throws Exception {
        AccessTokenPayload accessTokenPayload = new AccessTokenPayload();
        accessTokenPayload.setSub("sub");
        accessTokenPayload.setIss("iss");
        accessTokenPayload.setType(AccessTokenType.Cryptographic.intValue());
        accessTokenPayload.setVersion("1.0");
        accessTokenPayload.setJti("jti");
        accessTokenPayload.setIat(Instant.now().getEpochSecond());
        accessTokenPayload.setExp(Instant.now().getEpochSecond()+60*60);

        AccessTokenConditions accessTokenConditions = new AccessTokenConditions();
        accessTokenConditions.setHash("hash");
        accessTokenConditions.setLang("en-en");
        accessTokenConditions.setFnt("FNT");
        accessTokenConditions.setGnt("GNT");
        accessTokenConditions.setDob("12-12-2021");
        accessTokenConditions.setCoa("NL");
        accessTokenConditions.setCod("DE");
        accessTokenConditions.setRoa("AW");
        accessTokenConditions.setRod("BW");
        accessTokenConditions.setType(new String[] {"v"});
        accessTokenConditions.setValidationClock("2021-01-29T12:00:00+01:00");
        accessTokenConditions.setValidFrom("2021-01-29T12:00:00+01:00");
        accessTokenConditions.setValidTo("2021-01-30T12:00:00+01:00");


        accessTokenPayload.setConditions(accessTokenConditions);

        String accessTokenCompact = accessTokenBuilder.payload(accessTokenPayload).build(null, "kid");

        System.out.println(accessTokenCompact);

        AccessTokenPayload accessTokenParsed = accessTokenParser.parseToken(accessTokenCompact);
        assertNotNull(accessTokenParsed);
        assertNotNull(accessTokenParsed.getConditions());
    }
}