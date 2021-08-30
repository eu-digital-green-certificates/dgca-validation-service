package eu.europa.ec.dgc.validation.restapi.dto;

import lombok.Data;

@Data
public class AccessTokenConditions {
    private String hash;
    private String lang;
    /**
     * ICOA 930 transliterated surname (Familienname)
     */
    private String fnt;
    /**
     * ICOA 930 transliterated given name
     */
    private String gnt;
    /**
     * Date of birth.
     */
    private String dob;
    /**
     * Contry of Arrival
     */
    private String coa;
    /**
     * Country of Departure.
     */
    private String cod;
    /**
     * Region of Arrival ISO 3166-2 without Country.
     */
    private String roa;
    /**
     * Region of Departure ISO 3166-2 without Country.
     */
    private String rod;
    /**
     * Acceptable Type of DCC.
     */
    private String[] type;
    /**
     * Date where te DCC must be validateable.
     */
    private String validationClock;
    /**
     * DCC must be valid from this date (ISO8601 with offset)
     */
    private String validFrom;
    /**
     * DCC must be valid minimum to this date (ISO8601 with offset)
     */
    private String validTo;
}
