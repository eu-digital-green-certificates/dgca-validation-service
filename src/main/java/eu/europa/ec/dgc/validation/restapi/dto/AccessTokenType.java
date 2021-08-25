package eu.europa.ec.dgc.validation.restapi.dto;

public enum AccessTokenType {
    Structure(0), Cryptographic(1), Full(2);

    private final int intValue;

    AccessTokenType(int i) {
        intValue = i;
    }

    public int intValue() {
        return intValue;
    }
}
