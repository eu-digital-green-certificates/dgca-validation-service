package eu.europa.ec.dgc.validation.token;

import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenConditions;
import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenPayload;
import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenType;
import eu.europa.ec.dgc.validation.restapi.dto.ResultTypeIdentifier;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationStatusResponse;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationStatusResponse.Result.ResultType;
import eu.europa.ec.dgc.validation.service.ValidationServiceTest;
import io.jsonwebtoken.lang.Assert;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

public class ResultTokenBuilderTest {
    
    @Test
    void testTechnicalNOK()  {
       ValidationStatusResponse result = new ValidationStatusResponse();

       ValidationStatusResponse.Result r1 = new ValidationStatusResponse.Result();
       r1.setType(ResultTypeIdentifier.TechnicalVerification);
       r1.setResult(ResultType.NOK);
       ValidationStatusResponse.Result r2 = new ValidationStatusResponse.Result();
       r2.setType(ResultTypeIdentifier.TravellerAcceptance);
       r2.setResult(ResultType.CHK);
       result.setResults(new ArrayList<>());
       result.getResults().add(r1);
       result.getResults().add(r2);
       Assert.isTrue(ResultTokenBuilder.evaluateResult(result.getResults())=="NOK");
    }

    @Test
    void testTechnicalOKButFailedRule()  {
       ValidationStatusResponse result = new ValidationStatusResponse();

       ValidationStatusResponse.Result r1 = new ValidationStatusResponse.Result();
       r1.setType(ResultTypeIdentifier.TechnicalVerification);
       r1.setResult(ResultType.OK);
       ValidationStatusResponse.Result r2 = new ValidationStatusResponse.Result();
       r2.setType(ResultTypeIdentifier.TravellerAcceptance);
       r2.setResult(ResultType.NOK);
       result.setResults(new ArrayList<>());
       result.getResults().add(r1);
       result.getResults().add(r2);
       Assert.isTrue(ResultTokenBuilder.evaluateResult(result.getResults())=="CHK");
    }

    @Test
    void testTechnicalOKButFailedInvalidation()  {
       ValidationStatusResponse result = new ValidationStatusResponse();

       ValidationStatusResponse.Result r1 = new ValidationStatusResponse.Result();
       r1.setType(ResultTypeIdentifier.TechnicalVerification);
       r1.setResult(ResultType.OK);
       ValidationStatusResponse.Result r2 = new ValidationStatusResponse.Result();
       r2.setType(ResultTypeIdentifier.IssuerInvalidation);
       r2.setResult(ResultType.NOK);
       result.setResults(new ArrayList<>());
       result.getResults().add(r1);
       result.getResults().add(r2);
       Assert.isTrue(ResultTokenBuilder.evaluateResult(result.getResults())=="NOK");
    }

    @Test
    void testTechnicalOKButFailedInvalidation2()  {
       ValidationStatusResponse result = new ValidationStatusResponse();

       ValidationStatusResponse.Result r1 = new ValidationStatusResponse.Result();
       r1.setType(ResultTypeIdentifier.TechnicalVerification);
       r1.setResult(ResultType.OK);
       ValidationStatusResponse.Result r2 = new ValidationStatusResponse.Result();
       r2.setType(ResultTypeIdentifier.IssuerInvalidation);
       r2.setResult(ResultType.NOK);

       ValidationStatusResponse.Result r3 = new ValidationStatusResponse.Result();
       r3.setType(ResultTypeIdentifier.DestinationAcceptance);
       r3.setResult(ResultType.CHK);
       result.setResults(new ArrayList<>());
       result.getResults().add(r1);
       result.getResults().add(r2);
       result.getResults().add(r3);
       Assert.isTrue(ResultTokenBuilder.evaluateResult(result.getResults())=="NOK");
    }

    @Test
    void testTechnicalOKButRuleMustCheck()  {
       ValidationStatusResponse result = new ValidationStatusResponse();

       ValidationStatusResponse.Result r1 = new ValidationStatusResponse.Result();
       r1.setType(ResultTypeIdentifier.TechnicalVerification);
       r1.setResult(ResultType.OK);
       ValidationStatusResponse.Result r2 = new ValidationStatusResponse.Result();
       r2.setType(ResultTypeIdentifier.IssuerInvalidation);
       r2.setResult(ResultType.OK);

       ValidationStatusResponse.Result r3 = new ValidationStatusResponse.Result();
       r3.setType(ResultTypeIdentifier.DestinationAcceptance);
       r3.setResult(ResultType.CHK);
       result.setResults(new ArrayList<>());
       result.getResults().add(r1);
       result.getResults().add(r2);
       result.getResults().add(r3);
       Assert.isTrue(ResultTokenBuilder.evaluateResult(result.getResults())=="CHK");
    }
}
