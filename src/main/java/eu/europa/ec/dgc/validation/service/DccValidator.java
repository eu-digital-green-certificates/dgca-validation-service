package eu.europa.ec.dgc.validation.service;

import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenConditions;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationStatusResponse;
import java.util.ArrayList;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class DccValidator {

    public List<ValidationStatusResponse.Result> validate(String dcc, AccessTokenConditions accessTokenConditions) {
        List<ValidationStatusResponse.Result> results = new ArrayList<>();
        ValidationStatusResponse.Result result = new ValidationStatusResponse.Result();
        result.setResult(ValidationStatusResponse.Result.ResultType.OK);
        result.setType(ValidationStatusResponse.Result.Type.PASSED);
        result.setIdentifier("Junit");
        result.setDetails("Junit Mock Data");
        results.add(result);
        return results;
    }
}
