package eu.europa.ec.dgc.validation.restapi.dto;

import lombok.Data;

@Data
public class ValidationDevRequest {
    private String dcc;
    private AccessTokenPayload accessTokenPayload;
}
