package eu.europa.ec.dgc.validation.service;

import eu.europa.ec.dgc.validation.entity.ValidationInquiry;

public interface ValidationStoreService {
    void storeValidation(ValidationInquiry validationInquiry);

    ValidationInquiry receiveValidation(String subject);

    void updateValidation(ValidationInquiry validationInquiry);
}
