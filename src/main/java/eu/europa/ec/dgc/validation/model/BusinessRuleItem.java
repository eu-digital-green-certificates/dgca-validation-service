package eu.europa.ec.dgc.validation.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class BusinessRuleItem {

    private String hash;

    private String identifier;

    private String version;

    private String country;

    private String rawData;
}
