package eu.europa.ec.dgc.validation.restapi.dto;

public enum AcceptableType {
    Vaccination("v"), Test("t"), Recovery("r"), RATTest("tr"), PCRTest("tp");

    /**
     * see covid-19-lab-test type value set.
     */
    public static final String RAPID_TEST_TYPE = "LP217198-3";
    public static final String PCR_TEST_TYPE = "LP6464-4";

    private final String typeSymbol;

    AcceptableType(String typeSymbol) {
        this.typeSymbol = typeSymbol;
    }

    public String typeSymbol() {
        return typeSymbol;
    }

    public static AcceptableType getTokenForInt(String typeSymbol) {
        for (AcceptableType accessTokenType : AcceptableType.values()) {
            if (accessTokenType.typeSymbol.equals(typeSymbol)) {
                return accessTokenType;
            }
        }
        throw new IllegalArgumentException("unknown token type: "+typeSymbol);
    }
}
