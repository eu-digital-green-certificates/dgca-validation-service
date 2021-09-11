package eu.europa.ec.dgc.validation.restapi.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class AccessTokenPayload {
    private String jti;
    private String iss;
    private long iat;
    private String sub;
    private long exp;
    private int type;
    private String version;
    private AccessTokenConditions conditions;
}
