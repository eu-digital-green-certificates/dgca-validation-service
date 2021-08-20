package eu.europa.ec.dgc.validation.service;

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
        return null;
    }

    public ValidationStatusResponse checkValidationStatus(String subject) {
        return null;
    }
}
