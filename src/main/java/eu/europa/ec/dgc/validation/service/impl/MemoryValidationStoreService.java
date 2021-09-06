package eu.europa.ec.dgc.validation.service.impl;

import eu.europa.ec.dgc.validation.entity.ValidationInquiry;
import java.util.HashMap;

import eu.europa.ec.dgc.validation.service.ValidationStoreService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class MemoryValidationStoreService implements ValidationStoreService {
    private HashMap<String,ValidationInquiry> validationStore = new HashMap<>();

    @Override
    public void storeValidation(ValidationInquiry validationInquiry, long expirationTime) {
        validationStore.put(validationInquiry.getSubject(),validationInquiry);
    }

    @Override
    public ValidationInquiry receiveValidation(String subject) {
        return validationStore.get(subject);
    }

    @Override
    public void updateValidation(ValidationInquiry validationInquiry) {
        validationStore.put(validationInquiry.getSubject(),validationInquiry);
    }
}
