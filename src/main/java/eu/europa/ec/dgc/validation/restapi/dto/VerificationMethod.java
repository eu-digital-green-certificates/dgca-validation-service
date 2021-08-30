package eu.europa.ec.dgc.validation.restapi.dto;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.Data;

@Data
public class VerificationMethod {
    String Id;
    String type;
    String controller;
    PublicKeyJWK publicKeyJWK;
}
