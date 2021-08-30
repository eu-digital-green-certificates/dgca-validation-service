package eu.europa.ec.dgc.validation.restapi.dto;

import java.util.List;
import lombok.Data;

/**
 * Payload of validation response jwt token.
 */
@Data
public class ValidationStatusResponse {
    /**
     * Issuer of the validation.
     */
    private String issuer;
    /**
     * Number of seconds since epoch.
     */
    private int iat;
    /**
     * Value of the access token.
     */
    private String sub;
    private List<Result> results;
    /**
     * JWT string.
     */
    private String confirmation;

    @Data
    public static class Result {

        public enum Type { OPEN, FAILED, PASSED }

        public enum ResultType { CHK, OK, NOK }

        /**
         * Identifier of the check.
         */
        private String identifier;
        /**
         * Result of the check.
         */
        private ResultType result;
        /**
         * Type of the check.
         */
        private Type type;
        /**
         * Description of the checkup.
         */
        private String details;
    }
}
