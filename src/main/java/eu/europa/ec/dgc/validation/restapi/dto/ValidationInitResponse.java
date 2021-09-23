package eu.europa.ec.dgc.validation.restapi.dto;

import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.Data;

@Data
public class ValidationInitResponse {
    /**
     * Hexadecimal-encoded value.
     */
    @NotNull
    private String subject;
    /**
     * Number of seconds since January.
     * 1, 1970
     */
    private long exp;
    /**
     * Validation URL.
     */
    @NotNull
    private String aud;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private PublicKeyJwk encKey;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private PublicKeyJwk sigKey;
}
