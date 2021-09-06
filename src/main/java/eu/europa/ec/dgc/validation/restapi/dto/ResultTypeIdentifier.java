package eu.europa.ec.dgc.validation.restapi.dto;

public enum ResultTypeIdentifier {
    TechnicalVerification("Technical Verification"), IssuerInvalidation("Issuer Invalidation"),
    DestinationAcceptance("Destination Acceptance (V/T/R)"), TravellerAcceptance("Traveler Acceptance");

    private final String identifier;

    public String getIdentifier() {
        return identifier;
    }

    ResultTypeIdentifier(String identifier) {
        this.identifier = identifier;
    }
}
