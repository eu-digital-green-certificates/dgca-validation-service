package eu.europa.ec.dgc.validation.service;

public enum DccValidationMessage {
    PREFIX, BASE45, COMPRESSION, COSE, KID, SCHEMA, CBOR, EXPIRED, NOTVALIDYET, UNKNOWNISSUERCOUNTRY,
    HASH, HASH_NOT_MATCH("HASH"),
    NOTYETVALIDONDATE_BEFORE("NOTYETVALIDONDATE"),
    NOTYETVALIDONDATE_AFTER("NOTYETVALIDONDATE"),
    EXPIREDONDATE_BEFORE("EXPIREDONDATE"),
    EXPIREDONDATE_AFTER("EXPIREDONDATE"),
    SIGNATURE,
    KID_UNKNOWN("KID"),
    EXPIREDONCLOCK,
    FNTNOMATCH,
    GNTNOTMATCH,
    DOBNOMATCH,
    WRONGCERT;

    DccValidationMessage() {

    }

    DccValidationMessage(String identifier) {
        this.identifier = identifier;
    }

    private String identifier;

    /**
     * get identifier.
     * @return identifier
     */
    public String identifier() {
        if (identifier != null) {
            return identifier;
        } else {
            return name();
        }
    }
}
