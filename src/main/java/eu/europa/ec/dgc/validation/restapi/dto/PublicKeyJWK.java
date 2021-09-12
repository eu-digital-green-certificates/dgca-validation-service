package eu.europa.ec.dgc.validation.restapi.dto;

import lombok.Data;

@Data
public class PublicKeyJWK {
    private String x5c;
    private String kid;
    private String alg;
    private String use;
}
