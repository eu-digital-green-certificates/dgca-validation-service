package eu.europa.ec.dgc.validation.service;

import eu.europa.ec.dgc.validation.restapi.dto.DccValidationRequest;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationInitRequest;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationInitResponse;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationStatusResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Component
@Slf4j
@RequiredArgsConstructor
public class ValidationService {
    public ValidationInitResponse initValidation(ValidationInitRequest validationInitRequest) {
        // TODO init validation
        return null;
    }

    public String checkValidationStatus(String subject) {
        // TODO check validation status
        return null;
    }

    public String validate(DccValidationRequest dccValidationRequest) {
        // TODO validate dcc
        return null;
    }
}
