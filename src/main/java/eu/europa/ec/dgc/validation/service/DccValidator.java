package eu.europa.ec.dgc.validation.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import dgca.verifier.app.decoder.base45.Base45Service;
import dgca.verifier.app.decoder.base45.DefaultBase45Service;
import dgca.verifier.app.decoder.cbor.CborService;
import dgca.verifier.app.decoder.cbor.DefaultCborService;
import dgca.verifier.app.decoder.cbor.GreenCertificateData;
import dgca.verifier.app.decoder.compression.CompressorService;
import dgca.verifier.app.decoder.compression.DefaultCompressorService;
import dgca.verifier.app.decoder.cose.CoseService;
import dgca.verifier.app.decoder.cose.CryptoService;
import dgca.verifier.app.decoder.cose.DefaultCoseService;
import dgca.verifier.app.decoder.cose.VerificationCryptoService;
import dgca.verifier.app.decoder.model.CoseData;
import dgca.verifier.app.decoder.model.GreenCertificate;
import dgca.verifier.app.decoder.model.RecoveryStatement;
import dgca.verifier.app.decoder.model.Test;
import dgca.verifier.app.decoder.model.VerificationResult;
import dgca.verifier.app.decoder.prefixvalidation.DefaultPrefixValidationService;
import dgca.verifier.app.decoder.prefixvalidation.PrefixValidationService;
import dgca.verifier.app.decoder.schema.DefaultSchemaValidator;
import dgca.verifier.app.decoder.schema.SchemaValidator;
import dgca.verifier.app.decoder.services.X509;
import dgca.verifier.app.engine.CertLogicEngine;
import dgca.verifier.app.engine.DateTimeKt;
import dgca.verifier.app.engine.ValidationResult;
import dgca.verifier.app.engine.data.ExternalParameter;
import dgca.verifier.app.engine.data.Rule;
import dgca.verifier.app.engine.data.RuleCertificateType;
import dgca.verifier.app.engine.data.Type;
import eu.europa.ec.dgc.utils.CertificateUtils;
import eu.europa.ec.dgc.validation.exception.DccException;
import eu.europa.ec.dgc.validation.restapi.dto.AcceptableType;
import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenConditions;
import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenType;
import eu.europa.ec.dgc.validation.restapi.dto.ResultTypeIdentifier;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationStatusResponse;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Hashtable;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;
import javax.annotation.PostConstruct;
import kotlin.Triple;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpStatus;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class DccValidator {
    private PrefixValidationService prefixValidationService = new DefaultPrefixValidationService();
    private Base45Service base45Service = new DefaultBase45Service();
    private CompressorService compressorService = new DefaultCompressorService();
    private CoseService coseService = new DefaultCoseService();
    private CborService cborService = new DefaultCborService();
    private SchemaValidator schemaValidator = new DefaultSchemaValidator();
    private X509 x509 = new X509();
    private CryptoService cryptoService = new VerificationCryptoService(x509);
    private final SignerInformationService signerInformationService;
    private final CertLogicEngine certLogicEngine;
    private final CertificateUtils certificateUtils;
    private final ValueSetCache valueSetCache;
    private final RulesCache rulesCache;
    private final ResourceBundleMessageSource resourceBundleMessageSource;
    private final ObjectMapper objectMapper = new ObjectMapper();

    private static final ZoneId UTC_ZONE_ID = ZoneId.ofOffset("", ZoneOffset.UTC).normalized();

    /**
     * Tries to convert String into a version based on pattern majorVersion.minorVersion.patchVersion.
     */
    private static Triple<Integer, Integer, Integer> toVersion(String s) {
        try {
            String[] versionPieces = s.split("\\.");
            return new Triple<Integer,Integer,Integer>(Integer.valueOf(versionPieces[0]), 
                                                       Integer.valueOf(versionPieces[1]), 
                                                       Integer.valueOf(versionPieces[2]));
        } catch (Exception e) {
            return null;
        }
    }

    @PostConstruct
    public void initMapper() {
        objectMapper.registerModule(new JavaTimeModule());
    }

    /**
     * validate dcc.
     * @param dcc dcc
     * @param accessTokenConditions accessTokenConditions
     * @param accessTokenType accessTokenType
     * @param ignoreExpire ignoreExpire
     * @return results
     */
    public List<ValidationStatusResponse.Result> validate(String dcc,
                                                          AccessTokenConditions accessTokenConditions,
                                                          AccessTokenType accessTokenType, boolean ignoreExpire) {
        List<ValidationStatusResponse.Result> results = new ArrayList<>();
        VerificationResult verificationResult = new VerificationResult();
        String dccPlain = prefixValidationService.decode(dcc, verificationResult);
        Locale locale;
        if (accessTokenConditions.getLang() != null && accessTokenConditions.getLang().length() > 0) {
            locale = Locale.forLanguageTag(accessTokenConditions.getLang());
        } else {
            locale = Locale.ENGLISH;
        }
        if (verificationResult.getContextPrefix() == null) {
            addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                ResultTypeIdentifier.TechnicalVerification, DccValidationMessage.PREFIX, locale);
            return results;
        }
        byte[] compressedCose = base45Service.decode(dccPlain, verificationResult);
        if (!verificationResult.getBase45Decoded()) {
            addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                ResultTypeIdentifier.TechnicalVerification, DccValidationMessage.BASE45, locale);
            return results;
        }
        byte[] cose = compressorService.decode(compressedCose, verificationResult);
        if (cose == null || !verificationResult.getZlibDecoded()) {
            addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                ResultTypeIdentifier.TechnicalVerification, DccValidationMessage.COMPRESSION, locale);
            return results;
        }
        CoseData coseData = coseService.decode(cose, verificationResult);
        if (coseData == null) {
            addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                ResultTypeIdentifier.TechnicalVerification, DccValidationMessage.COSE, locale);
            return results;
        }
        if (coseData.getKid() == null) {
            addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                ResultTypeIdentifier.TechnicalVerification, DccValidationMessage.KID, locale);
            return results;
        }
        schemaValidator.validate(coseData.getCbor(), verificationResult);
        if (!verificationResult.isSchemaValid()) {
            addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                ResultTypeIdentifier.TechnicalVerification, DccValidationMessage.SCHEMA, locale);
            return results;
        }
        GreenCertificateData greenCertificateData = cborService.decodeData(coseData.getCbor(), verificationResult);
        if (!verificationResult.getCborDecoded()) {
            addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                ResultTypeIdentifier.TechnicalVerification, DccValidationMessage.CBOR, locale);
            return results;
        }

        if (ZonedDateTime.now().isAfter(greenCertificateData.getExpirationTime()) && !ignoreExpire) {
            addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                ResultTypeIdentifier.TechnicalVerification, DccValidationMessage.EXPIRED, locale);
            return results;
        }

        if (ZonedDateTime.now().isBefore(greenCertificateData.getIssuedAt())) {
            addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                ResultTypeIdentifier.TechnicalVerification, DccValidationMessage.NOTVALIDYET, locale);
            return results;
        }

        if (!Arrays.asList(Locale.getISOCountries()).contains(greenCertificateData.getIssuingCountry())) {
            addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                ResultTypeIdentifier.TechnicalVerification, DccValidationMessage.UNKNOWNISSUERCOUNTRY, locale);
            return results;
        }

        addResult(results, ValidationStatusResponse.Result.ResultType.OK,
            ResultTypeIdentifier.TechnicalVerification, "STRUCTURE", "OK");
        if (accessTokenConditions == null) {
            throw new DccException("Validation Conditions missing", HttpStatus.SC_BAD_REQUEST);
        }

        if (accessTokenType == AccessTokenType.Structure) {
            if (accessTokenConditions.getHash() == null || accessTokenConditions.getHash().length() == 0) {
                addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                    ResultTypeIdentifier.TechnicalVerification, DccValidationMessage.HASH, locale);
            } else {
                try {
                    if (!certificateUtils.calculateHash(dcc.getBytes(StandardCharsets.UTF_8))
                        .equals(accessTokenConditions.getHash())) {
                        addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                            ResultTypeIdentifier.TechnicalVerification, DccValidationMessage.HASH_NOT_MATCH, locale);
                    } else {
                        addResult(results, ValidationStatusResponse.Result.ResultType.OK,
                            ResultTypeIdentifier.TechnicalVerification, "HASH", "OK");
                    }
                } catch (NoSuchAlgorithmException e) {
                    throw new DccException("hash calculation", e);
                }
            }
        }

        checkExpirationDates(greenCertificateData, accessTokenConditions, results, locale);
        checkAcceptableCertType(greenCertificateData, accessTokenConditions, results, locale);
        if (accessTokenType.intValue() > AccessTokenType.Structure.intValue()) {
            validateGreenCertificateNameDob(greenCertificateData, accessTokenConditions, results, locale);
            validateCryptographic(cose, coseData.getKid(), accessTokenConditions, verificationResult, results, locale);
            if (accessTokenType == AccessTokenType.Full) {
                validateRules(greenCertificateData, verificationResult, results, accessTokenConditions,
                    coseData.getKid(), rulesCache, valueSetCache, locale);
            }
        }

        return results;
    }

    private void checkExpirationDates(GreenCertificateData greenCertificateData,
                                      AccessTokenConditions accessTokenConditions,
                                      List<ValidationStatusResponse.Result> results, Locale locale) {
        ZonedDateTime validFrom = ZonedDateTime.parse(accessTokenConditions.getValidFrom());
        ZonedDateTime validTo = ZonedDateTime.parse(accessTokenConditions.getValidTo());
        if (!greenCertificateData.getExpirationTime().isAfter(validTo)) {
            addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                ResultTypeIdentifier.TechnicalVerification, DccValidationMessage.EXPIREDONDATE_AFTER, locale);
        }
        if (greenCertificateData.getGreenCertificate().getType()
            == dgca.verifier.app.decoder.model.CertificateType.TEST) {
            Test testStatement = greenCertificateData.getGreenCertificate().getTests().get(0);
            ZonedDateTime dateOfCollection = toZonedDateTimeOrUtcLocal(testStatement.getDateTimeOfCollection());
            if (dateOfCollection != null && !dateOfCollection.isBefore(validFrom)) {
                addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                    ResultTypeIdentifier.TechnicalVerification, DccValidationMessage.NOTYETVALIDONDATE_TEST, locale);
            }
        } else if (greenCertificateData.getGreenCertificate().getType()
            == dgca.verifier.app.decoder.model.CertificateType.RECOVERY) {
            RecoveryStatement recoveryStatement =
                greenCertificateData.getGreenCertificate().getRecoveryStatements().get(0);
            ZonedDateTime certValidFrom = toZonedDateTimeOrUtcLocal(recoveryStatement.getCertificateValidFrom());
            ZonedDateTime certValidTo = toZonedDateTimeOrUtcLocal(recoveryStatement.getCertificateValidUntil());
            if (certValidFrom != null && !certValidFrom.isBefore(validFrom)) {
                addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                    ResultTypeIdentifier.TechnicalVerification,
                        DccValidationMessage.NOTYETVALIDONDATE_RECOVERY, locale);
            }
            if (certValidTo != null && !certValidTo.isAfter(validTo)) {
                addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                    ResultTypeIdentifier.TechnicalVerification, DccValidationMessage.EXPIREDONDATE_RECOVERY, locale);
            }
        }
    }

    ZonedDateTime toZonedDateTimeOrUtcLocal(String dateTime) {
        ZonedDateTime zonedDateTime;
        try {
            zonedDateTime = ZonedDateTime.parse(dateTime).withZoneSameInstant(UTC_ZONE_ID);
        } catch (DateTimeParseException dateTimeParseException) {
            try {
                zonedDateTime = LocalDateTime.parse(dateTime).atZone(UTC_ZONE_ID);
            } catch (DateTimeParseException dateTimeParseException1) {
                try {
                    zonedDateTime = LocalDate.parse(dateTime).atStartOfDay(UTC_ZONE_ID);
                } catch (DateTimeParseException dateTimeParseException2) {
                    zonedDateTime = null;
                }
            }
        }
        return zonedDateTime;
    }

    /**
     * validate rules.
     * @param greenCertificateData greenCertificateData
     * @param verificationResult verificationResult
     * @param results results
     * @param accessTokenConditions accessTokenConditions
     * @param kid kid
     * @param rulesCache rulesCache
     * @param valueSetCache valueSetCache
     */
    void validateRules(GreenCertificateData greenCertificateData,
                                     VerificationResult verificationResult,
                                     List<ValidationStatusResponse.Result> results,
                                     AccessTokenConditions accessTokenConditions,
                                     byte[] kid,
                                     RulesCache rulesCache,
                                     ValueSetCache valueSetCache, Locale locale) {
        log.debug("Start BusinessRule Evaluation");
        ZonedDateTime validationClock = ZonedDateTime.parse(accessTokenConditions.getValidationClock());

        String countryOfArrival = accessTokenConditions.getCoa();
        String regionOfArrival = accessTokenConditions.getRoa().isEmpty() ? null : accessTokenConditions.getRoa();
        String certificateType = greenCertificateData.getGreenCertificate().getType().toString();
        List<Rule> rules = rulesCache.provideRules(countryOfArrival, greenCertificateData.getIssuingCountry());
        log.debug("Found Rules: " + rules.size());
        rules = rules.stream()
            .peek(t -> {
                log.debug(String.format("Identifier: %s,Type: %s , Country: %s, CertType: %s",
                    t.getIdentifier(), t.getType(), t.getCountryCode(), t.getRuleCertificateType()));
                log.debug("General :"
                    + String.valueOf(
                        t.getRuleCertificateType().toString().toLowerCase().equals(certificateType.toLowerCase())
                            || t.getRuleCertificateType().toString().equals("General")));
                log.debug("Clock :" + String.valueOf((t.getValidFrom().isBefore(validationClock)
                    || t.getValidFrom().isEqual(validationClock))));
                log.debug("Type :" + String.valueOf(t.getType() == dgca.verifier.app.engine.data.Type.ACCEPTANCE));
                log.debug("Country :" + String.valueOf(t.getCountryCode().equals(countryOfArrival)));
                log.debug("Region :" + String.valueOf((t.getRegion() == null
                    || t.getRegion().equals(regionOfArrival))));
                log.debug("InvalidType :"
                    + String.valueOf(t.getType() == dgca.verifier.app.engine.data.Type.INVALIDATION));
                log.debug("IssuerCountry :"
                    + String.valueOf(t.getCountryCode().equals(greenCertificateData.getIssuingCountry())));
            })
            .filter(t -> ((t.getRuleCertificateType().toString().toLowerCase().equals(certificateType.toLowerCase())
                || t.getRuleCertificateType().toString().equals("General"))
                    && (t.getValidFrom().isBefore(validationClock) || t.getValidFrom().isEqual(validationClock))
                    && t.getType() == dgca.verifier.app.engine.data.Type.ACCEPTANCE)
                    && t.getCountryCode().toLowerCase().equals(countryOfArrival.toLowerCase())
                    && (t.getRegion() == null || t.getRegion().toLowerCase().equals(regionOfArrival.toLowerCase()))
                    || (
                        (t.getRuleCertificateType().toString().toLowerCase().equals(certificateType.toLowerCase())
                            || t.getRuleCertificateType().toString().equals("General"))
                            && (t.getValidFrom().isBefore(validationClock) || t.getValidFrom().isEqual(validationClock))
                            && t.getType() == dgca.verifier.app.engine.data.Type.INVALIDATION
                            && t.getCountryCode().toLowerCase()
                                .equals(greenCertificateData.getIssuingCountry().toLowerCase())
                    )
            )
            .map(t -> t)
            .collect(Collectors.toList());
        Hashtable<String,Triple<Integer,Integer,Integer>> identifierVersions = 
                                                                new Hashtable<String,Triple<Integer,Integer,Integer>>();
        Hashtable<String,Rule> ruleVersions = new Hashtable<String,Rule>();
        ArrayList<Rule> rulesOut = new ArrayList<Rule>();
        for (Rule rule : rules) {
            if (!identifierVersions.containsKey(rule.getIdentifier())) {
                identifierVersions.put(rule.getIdentifier(), toVersion(rule.getVersion()));
                ruleVersions.put(rule.getIdentifier(), rule);
            }
            var currVersion = toVersion(rule.getVersion());
            var prevVersion = identifierVersions.get(rule.getIdentifier());

            if (currVersion != null && prevVersion != null) {
                if (currVersion.component1() < prevVersion.component1()) {
                    rulesOut.add(rule); 
                    continue;   
                }

                if (currVersion.component1() > prevVersion.component1()) {
                    rulesOut.add(ruleVersions.get(rule.getIdentifier()));
                    ruleVersions.put(rule.getIdentifier(), rule);
                    identifierVersions.put(rule.getIdentifier(), currVersion);
                    continue;
                }

                if (currVersion.component1() == prevVersion.component1()) {
                    if (currVersion.component2() < prevVersion.component2()) {
                        rulesOut.add(rule);
                        continue;   
                    }

                    if (currVersion.component2() > prevVersion.component2()) {
                        rulesOut.add(ruleVersions.get(rule.getIdentifier()));
                        ruleVersions.put(rule.getIdentifier(), rule);
                        identifierVersions.put(rule.getIdentifier(), currVersion);
                        continue;
                    }

                    if (currVersion.component2() == prevVersion.component2()) {
                        if (currVersion.component3() < prevVersion.component3()) {
                            rulesOut.add(rule);
                            continue;   
                        }

                        if (currVersion.component3() > prevVersion.component3()) {
                            rulesOut.add(ruleVersions.get(rule.getIdentifier()));
                            ruleVersions.put(rule.getIdentifier(), rule);
                            identifierVersions.put(rule.getIdentifier(), currVersion);
                            continue;
                        }
                    }
                }
            }
        }

        rules.removeAll(rulesOut);
            
        log.debug("Matching Rules: " + rules.size());
        if (rules != null && rules.size() > 0) {
            String kidBase64 = Base64.getEncoder().encodeToString(kid);
            Map<String, List<String>> valueSets = valueSetCache.provideValueSets();
            ExternalParameter externalParameter = new ExternalParameter(validationClock, valueSets, countryOfArrival,
                greenCertificateData.getExpirationTime(),
                greenCertificateData.getIssuedAt(),
                greenCertificateData.getIssuingCountry(),
                kidBase64,
                accessTokenConditions.getRoa()
            );
            String hcertJson = greenCertificateData.getHcertJson();
            dgca.verifier.app.engine.data.CertificateType certEngineType;
            switch (greenCertificateData.getGreenCertificate().getType()) {
                case RECOVERY:
                    certEngineType = dgca.verifier.app.engine.data.CertificateType.RECOVERY;
                    break;
                case VACCINATION:
                    certEngineType = dgca.verifier.app.engine.data.CertificateType.VACCINATION;
                    break;
                default:
                    certEngineType = dgca.verifier.app.engine.data.CertificateType.TEST;
            }
            List<ValidationResult> ruleValidationResults = certLogicEngine.validate(certEngineType,
                greenCertificateData.getGreenCertificate().getSchemaVersion(),
                rules, externalParameter, hcertJson);

            for (ValidationResult validationResult : ruleValidationResults) {
                ValidationStatusResponse.Result.ResultType resultType;
                switch (validationResult.getResult()) {
                    case OPEN:
                        resultType = ValidationStatusResponse.Result.ResultType.CHK;
                        break;
                    case PASSED:
                        resultType = ValidationStatusResponse.Result.ResultType.OK;
                        break;
                    default:
                        resultType = ValidationStatusResponse.Result.ResultType.NOK;
                        break;
                }
                StringBuilder details = new StringBuilder();
                details.append(validationResult.getRule().getIdentifier()).append(' ');
                details.append(validationResult.getRule().getDescriptionFor(locale.getLanguage())).append(' ');
                if (validationResult.getCurrent() != null && validationResult.getCurrent().length() > 0) {
                    details.append(validationResult.getCurrent()).append(' ');
                }
                if (validationResult.getValidationErrors() != null
                    && validationResult.getValidationErrors().size() > 0) {
                    details.append(" Exceptions: ");
                    for (Exception exception : validationResult.getValidationErrors()) {
                        details.append(exception.getMessage()).append(' ');
                    }
                }
                ResultTypeIdentifier resultTypeIdentifier = ResultTypeIdentifier.DestinationAcceptance;
                if (validationResult.getRule() != null) {
                    if (validationResult.getRule().getType() == Type.INVALIDATION) {
                        resultTypeIdentifier = ResultTypeIdentifier.IssuerInvalidation;
                    } else if (validationResult.getRule().getType() == Type.ACCEPTANCE) {
                        if (validationResult.getRule().getRuleCertificateType() == RuleCertificateType.GENERAL) {
                            resultTypeIdentifier = ResultTypeIdentifier.TravellerAcceptance;
                        } else {
                            resultTypeIdentifier = ResultTypeIdentifier.DestinationAcceptance;
                        }
                    }
                    addResult(results, resultType, resultTypeIdentifier,
                        validationResult.getRule().getIdentifier(), details.toString());
                }
            }
        }
    }

    private void validateCryptographic(byte[] cose, byte[] kid,
                                       AccessTokenConditions accessTokenConditions,
                                       VerificationResult verificationResult,
                                       List<ValidationStatusResponse.Result> results, Locale locale) {
        ZonedDateTime validationClock = ZonedDateTime.parse(accessTokenConditions.getValidationClock());
        String kidBase64 = Base64.getEncoder().encodeToString(kid);
        List<Certificate> certificates = signerInformationService.getCertificates(kidBase64);
        if (certificates != null && certificates.size() > 0) {
            boolean signValidated = false;
            for (Certificate certificate : certificates) {
                cryptoService.validate(cose, certificate, verificationResult);
                if (verificationResult.getCoseVerified()) {
                    ZonedDateTime expirationTime = (certificate instanceof X509Certificate)
                        ? ((X509Certificate) certificate).getNotAfter()
                            .toInstant().atZone(DateTimeKt.getUTC_ZONE_ID())
                        : null;
                    if (expirationTime != null && validationClock.isAfter(expirationTime)) {
                        addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                            ResultTypeIdentifier.TechnicalVerification, DccValidationMessage.EXPIREDONCLOCK, locale);
                    }
                    signValidated = true;
                    break;
                }
            }
            if (!signValidated) {
                addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                    ResultTypeIdentifier.TechnicalVerification, DccValidationMessage.SIGNATURE, locale);
            } else {
                addResult(results, ValidationStatusResponse.Result.ResultType.OK,
                    ResultTypeIdentifier.TechnicalVerification, "SIGNATURE", "signature valid");
            }
        } else {
            addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                ResultTypeIdentifier.TechnicalVerification, DccValidationMessage.KID_UNKNOWN, locale);
        }
    }

    private void validateGreenCertificateNameDob(GreenCertificateData greenCertificateData,
                                                 AccessTokenConditions accessTokenConditions,
                                                 List<ValidationStatusResponse.Result> results, Locale locale) {
        if (greenCertificateData.getGreenCertificate().getPerson().getStandardisedFamilyName() == null
            || !greenCertificateData.getGreenCertificate().getPerson()
                .getStandardisedFamilyName().equals(accessTokenConditions.getFnt())) {
            addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                ResultTypeIdentifier.TechnicalVerification,  DccValidationMessage.FNTNOMATCH, locale);
        }
        if (greenCertificateData.getGreenCertificate().getPerson().getStandardisedGivenName() == null
            || !greenCertificateData.getGreenCertificate().getPerson()
                .getStandardisedGivenName().equals(accessTokenConditions.getGnt())) {
            addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                ResultTypeIdentifier.TechnicalVerification,  DccValidationMessage.GNTNOTMATCH, locale);
        }
        if (greenCertificateData.getGreenCertificate().getDateOfBirth() == null
            ||  !greenCertificateData.getGreenCertificate().getDateOfBirth().equals(accessTokenConditions.getDob())) {
            addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                ResultTypeIdentifier.TechnicalVerification,  DccValidationMessage.DOBNOMATCH, locale);
        }
    }

    private void checkAcceptableCertType(GreenCertificateData greenCertificateData,
                                         AccessTokenConditions accessTokenConditions,
                                         List<ValidationStatusResponse.Result> results, Locale locale) {
        if (accessTokenConditions.getType() != null) {
            boolean accepted = false;
            for (String acceptableTypeSymbol : accessTokenConditions.getType()) {
                AcceptableType acceptableType = AcceptableType.getTokenForSymbol(acceptableTypeSymbol);
                switch (acceptableType) {
                    case Vaccination:
                        accepted = greenCertificateData.getGreenCertificate().getType()
                            == dgca.verifier.app.decoder.model.CertificateType.VACCINATION;
                        break;
                    case Recovery:
                        accepted = greenCertificateData.getGreenCertificate().getType()
                            == dgca.verifier.app.decoder.model.CertificateType.RECOVERY;
                        break;
                    case Test:
                        accepted = greenCertificateData.getGreenCertificate().getType()
                            == dgca.verifier.app.decoder.model.CertificateType.TEST;
                        break;
                    case PCRTest:
                        accepted = isPcrTest(greenCertificateData.getGreenCertificate());
                        break;
                    case RATTest:
                        accepted = isRatTest(greenCertificateData.getGreenCertificate());
                        break;
                    default:
                        break;
                }
                if (accepted) {
                    break;
                }
            }
            if (!accepted) {
                addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                    ResultTypeIdentifier.TechnicalVerification,
                        DccValidationMessage.WRONGCERT, locale);
            }
        }
    }

    private boolean isRatTest(GreenCertificate greenCertificate) {
        boolean ratTest;
        if (greenCertificate.getType() == dgca.verifier.app.decoder.model.CertificateType.TEST
            && greenCertificate.getTests() != null && greenCertificate.getTests().size() > 0
        ) {
            ratTest = AcceptableType.RAPID_TEST_TYPE.equals(greenCertificate.getTests().get(0).getTypeOfTest());
        } else {
            ratTest = false;
        }
        return ratTest;
    }

    private boolean isPcrTest(GreenCertificate greenCertificate) {
        boolean pcrTest;
        if (greenCertificate.getType() == dgca.verifier.app.decoder.model.CertificateType.TEST
            && greenCertificate.getTests() != null && greenCertificate.getTests().size() > 0) {
            pcrTest = AcceptableType.PCR_TEST_TYPE.equals(greenCertificate.getTests().get(0).getTypeOfTest());
        } else {
            pcrTest = false;
        }
        return pcrTest;
    }

    private void addResult(List<ValidationStatusResponse.Result> results,
                                  ValidationStatusResponse.Result.ResultType resultType,
                                  ResultTypeIdentifier type, String identifier, String details) {
        ValidationStatusResponse.Result result = new ValidationStatusResponse.Result();
        result.setResult(resultType);
        result.setType(type);
        result.setIdentifier(identifier);
        result.setDetails(details);
        results.add(result);
    }

    private void addResult(List<ValidationStatusResponse.Result> results,
                                  ValidationStatusResponse.Result.ResultType resultType,
                                  ResultTypeIdentifier type, DccValidationMessage dccValidationMessage, Locale locale) {
        addResult(results, resultType, type, dccValidationMessage.identifier(),
                resourceBundleMessageSource.getMessage(dccValidationMessage.name(), null, locale));
    }
}