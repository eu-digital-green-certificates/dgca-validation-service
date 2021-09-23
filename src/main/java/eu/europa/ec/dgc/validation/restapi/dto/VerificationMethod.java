package eu.europa.ec.dgc.validation.restapi.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class VerificationMethod {
    String id;
    String type;
    String controller;
    PublicKeyJwk publicKeyJwk;
}
