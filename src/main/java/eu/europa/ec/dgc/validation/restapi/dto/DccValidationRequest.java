package eu.europa.ec.dgc.validation.restapi.dto;

import lombok.Data;

@Data
public class DccValidationRequest {
    private String kid;
    private String dcc;
    private String sig;
    private String sigAlg;
    private String encScheme;
    private String encKey;
}
