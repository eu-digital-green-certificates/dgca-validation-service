package eu.europa.ec.dgc.validation.service;

import eu.europa.ec.dgc.validation.entity.ValidationInquiry;
import java.util.HashMap;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class ValidationStoreService {
    private HashMap<String,ValidationInquiry> validationStore = new HashMap<>();

    public void storeValidation(ValidationInquiry validationInquiry) {
        validationStore.put(validationInquiry.getSubject(),validationInquiry);
    }

    public ValidationInquiry receiveValidation(String subject) {
        return validationStore.get(subject);
    }

}
