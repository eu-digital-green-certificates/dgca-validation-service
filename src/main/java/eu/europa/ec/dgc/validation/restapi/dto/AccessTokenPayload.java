package eu.europa.ec.dgc.validation.restapi.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class AccessTokenPayload {
    private String jti;
    private String iss;
    private long iat;
    private String sub;
    private String aud;
    private long exp;
    @JsonProperty("t")
    private int type;
    @JsonProperty("v")
    private String version;
    @JsonProperty("vc")
    private AccessTokenConditions conditions;
}
