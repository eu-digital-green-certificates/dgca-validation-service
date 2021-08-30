package eu.europa.ec.dgc.validation.restapi.dto;

import javax.validation.constraints.NotNull;
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
}
