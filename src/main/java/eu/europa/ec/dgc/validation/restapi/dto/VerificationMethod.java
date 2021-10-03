package eu.europa.ec.dgc.validation.restapi.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

@Data
public class VerificationMethod {
    String id;
    String type;
    String controller;
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    PublicKeyJwk publicKeyJwk;
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    String[] verificationMethods;
}
