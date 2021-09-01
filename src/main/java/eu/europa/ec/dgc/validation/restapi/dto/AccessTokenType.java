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

    public static AccessTokenType getTokenForInt(int intValue) {
        for (AccessTokenType accessTokenType : AccessTokenType.values()) {
            if (accessTokenType.intValue==intValue) {
                return accessTokenType;
            }
        }
        throw new IllegalArgumentException("unknown token type: "+intValue);
    }
}
