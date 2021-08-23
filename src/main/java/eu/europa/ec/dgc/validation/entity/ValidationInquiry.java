package eu.europa.ec.dgc.validation.entity;

import lombok.Data;

@Data
public class ValidationInquiry {
    public enum ValidationStatus { OPEN, READY }

    private String subject;
    private ValidationStatus validationStatus;
    private String validationResult;
    private String publicKey;
    private String keyType;
    private long exp;
}
