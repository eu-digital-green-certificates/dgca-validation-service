package eu.europa.ec.dgc.validation.service;

import com.fasterxml.jackson.core.JsonProcessingException;
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
import dgca.verifier.app.decoder.model.VerificationResult;
import dgca.verifier.app.decoder.prefixvalidation.DefaultPrefixValidationService;
import dgca.verifier.app.decoder.prefixvalidation.PrefixValidationService;
import dgca.verifier.app.decoder.schema.DefaultSchemaValidator;
import dgca.verifier.app.decoder.schema.SchemaValidator;
import dgca.verifier.app.decoder.services.X509;
import dgca.verifier.app.engine.CertLogicEngine;
import dgca.verifier.app.engine.DateTimeKt;
import dgca.verifier.app.engine.ValidationResult;
import dgca.verifier.app.engine.data.CertificateType;
import dgca.verifier.app.engine.data.ExternalParameter;
import dgca.verifier.app.engine.data.Rule;
import dgca.verifier.app.engine.data.ValueSet;
import dgca.verifier.app.engine.data.source.remote.rules.RuleRemote;
import dgca.verifier.app.engine.data.source.remote.rules.RuleRemoteMapperKt;
import dgca.verifier.app.engine.data.source.remote.valuesets.ValueSetRemote;
import eu.europa.ec.dgc.validation.entity.BusinessRuleEntity;
import eu.europa.ec.dgc.validation.entity.ValueSetEntity;
import eu.europa.ec.dgc.validation.exception.DccException;
import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenConditions;
import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenType;
import eu.europa.ec.dgc.validation.restapi.dto.BusinessRuleListItemDto;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationStatusResponse;
import eu.europa.ec.dgc.validation.restapi.dto.ValueSetListItemDto;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import javax.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.jetbrains.annotations.NotNull;
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
    private final BusinessRuleService businessRuleService;
    private final CertLogicEngine certLogicEngine;
    private final ValueSetService valueSetService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @PostConstruct
    public void initMapper() {
        objectMapper.registerModule(new JavaTimeModule());
    }

    public List<ValidationStatusResponse.Result> validate(String dcc, AccessTokenConditions accessTokenConditions, AccessTokenType accessTokenType) {
        List<ValidationStatusResponse.Result> results = new ArrayList<>();

        VerificationResult verificationResult = new VerificationResult();
        String dccPlain = prefixValidationService.decode(dcc,verificationResult);
        if (verificationResult.getContextPrefix()==null) {
            addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                    ValidationStatusResponse.Result.Type.FAILED,"Prefix Validation","No HC1: prefix");
            return results;
        }
        byte[] compressedCose = base45Service.decode(dccPlain, verificationResult);
        if (!verificationResult.getBase45Decoded()) {
            addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                    ValidationStatusResponse.Result.Type.FAILED,"Base45 decode","Wrong Base45 coding");
            return results;
        }
        byte[] cose = compressorService.decode(compressedCose, verificationResult);
        if (cose==null || !verificationResult.getZlibDecoded()) {
            addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                    ValidationStatusResponse.Result.Type.FAILED,"Data Decompress","Can not decompress data");
            return results;
        }
        CoseData coseData = coseService.decode(cose, verificationResult);
        if (coseData==null) {
            addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                    ValidationStatusResponse.Result.Type.FAILED,"Cose decoding","Can not decode cose");
            return results;
        }
        if (coseData.getKid()==null) {
            addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                    ValidationStatusResponse.Result.Type.FAILED,"Cose decoding","Can not extract kid");
            return results;
        }
        schemaValidator.validate(coseData.getCbor(),verificationResult);
        if (!verificationResult.isSchemaValid()) {
            addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                    ValidationStatusResponse.Result.Type.FAILED,"Schema Validation","schema invalid");
            return results;
        }
        GreenCertificateData greenCertificateData = cborService.decodeData(coseData.getCbor(), verificationResult);
        if (!verificationResult.getCborDecoded()) {
            addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                    ValidationStatusResponse.Result.Type.FAILED,"CBOR Decoding","can not decode cbor");
            return results;
        }
        addResult(results, ValidationStatusResponse.Result.ResultType.OK,
                ValidationStatusResponse.Result.Type.PASSED, "Structure", "OK");
        validateGreenCertificateData(greenCertificateData, accessTokenConditions, results);
        if (accessTokenType.intValue()>AccessTokenType.Structure.intValue()) {
            validateCryptographic(cose, coseData.getKid(), accessTokenConditions, verificationResult, results);
            if (accessTokenType==AccessTokenType.Full) {
                validateRules(greenCertificateData, verificationResult, results, accessTokenConditions, coseData.getKid());
            }
        }
        if (results.isEmpty()) {
            addResult(results, ValidationStatusResponse.Result.ResultType.OK,
                    ValidationStatusResponse.Result.Type.PASSED, "OK", "OK");
        }

        return results;
    }

    private void validateRules(GreenCertificateData greenCertificateData, VerificationResult verificationResult,
                               List<ValidationStatusResponse.Result> results, AccessTokenConditions accessTokenConditions, byte[] kid) {
        String countryOfDeparture = accessTokenConditions.getCod();
        List<Rule> rules = provideRules(countryOfDeparture);
        if (rules!=null && rules.size()>0) {
            ZonedDateTime validationClock = ZonedDateTime.parse(accessTokenConditions.getValidationClock());
            String kidBase64 = Base64.getEncoder().encodeToString(kid);
            Map<String, List<String>> valueSets = provideValueSets();
            ExternalParameter externalParameter = new ExternalParameter(validationClock, valueSets, countryOfDeparture,
                    greenCertificateData.getExpirationTime(),
                    greenCertificateData.getIssuedAt(),
                    greenCertificateData.getIssuingCountry(),
                    kidBase64,
                    ""
                    );
            String hcertJson = greenCertificateData.getHcertJson();
            CertificateType certEngineType;
            switch (greenCertificateData.getGreenCertificate().getType()) {
                case RECOVERY:
                    certEngineType = CertificateType.RECOVERY;
                    break;
                case VACCINATION:
                    certEngineType = CertificateType.VACCINATION;
                    break;
                default:
                    certEngineType = CertificateType.TEST;
            }
            List<ValidationResult> ruleValidationResults = certLogicEngine.validate(certEngineType, greenCertificateData.getGreenCertificate().getSchemaVersion(),
                    rules, externalParameter, hcertJson);
            for (ValidationResult validationResult : ruleValidationResults) {
                ValidationStatusResponse.Result.Type type;
                ValidationStatusResponse.Result.ResultType resultType;
                switch (validationResult.getResult()) {
                    case OPEN:
                        type = ValidationStatusResponse.Result.Type.OPEN;
                        resultType = ValidationStatusResponse.Result.ResultType.NOK;
                        break;
                    case PASSED:
                        type = ValidationStatusResponse.Result.Type.PASSED;
                        resultType = ValidationStatusResponse.Result.ResultType.OK;
                        break;
                    default:
                        type = ValidationStatusResponse.Result.Type.FAILED;
                        resultType = ValidationStatusResponse.Result.ResultType.NOK;
                        break;
                }
                StringBuilder details = new StringBuilder();
                details.append(validationResult.getRule().getIdentifier()).append(' ');
                details.append(validationResult.getRule().getDescriptionFor("en")).append(' ');
                if (validationResult.getCurrent()!=null && validationResult.getCurrent().length()>0) {
                    details.append(validationResult.getCurrent()).append(' ');
                }
                if (validationResult.getValidationErrors()!=null && validationResult.getValidationErrors().size()>0) {
                    details.append(" Exceptions: ");
                    for (Exception exception : validationResult.getValidationErrors()) {
                        details.append(exception.getMessage()).append(' ');
                    }
                }

                addResult(results, resultType, type, "Rules", details.toString());
            }
        } else {
            addResult(results, ValidationStatusResponse.Result.ResultType.OK,
                    ValidationStatusResponse.Result.Type.PASSED, "Rules", "No rules for country of departure defined");
        }
    }

    @NotNull
    private List<Rule> provideRules(String countryOfDeparture) {
        List<BusinessRuleListItemDto> rulesDto = businessRuleService.getBusinessRulesListForCountry(countryOfDeparture);
        List<Rule> rules = new ArrayList<>();
        for (BusinessRuleListItemDto ruleDto : rulesDto) {
            BusinessRuleEntity ruleData = businessRuleService.getBusinessRuleByCountryAndHash(ruleDto.getCountry(), ruleDto.getHash());
            if (ruleData!=null) {
                try {
                    RuleRemote ruleRemote = objectMapper.readValue(ruleData.getRawData(), RuleRemote.class);
                    rules.add(RuleRemoteMapperKt.toRule(ruleRemote));
                } catch (JsonProcessingException e) {
                    throw new DccException("can not parse rule", e);
                }
            }
        }
        return rules;
    }

    @NotNull
    private Map<String, List<String>> provideValueSets() {
        Map<String, List<String>> valueSets = new HashMap<>();
        for (ValueSetListItemDto valueSetListItemDto : valueSetService.getValueSetsList()) {
            ValueSetEntity valueSetEntity = valueSetService.getValueSetByHash(valueSetListItemDto.getHash());
            try {
                ValueSetRemote valueSet = objectMapper.readValue(valueSetEntity.getRawData(), ValueSetRemote.class);
                List<String> ids = new ArrayList<>();
                for (Iterator<String> it = valueSet.getValueSetValues().fieldNames(); it.hasNext(); ) {
                    String fieldName = it.next();
                    ids.add(fieldName);
                }
                valueSets.put(valueSetEntity.getId(), ids);
            } catch (JsonProcessingException e) {
                throw new DccException("can not parse value list",e);
            }
        }
        return valueSets;
    }

    private void validateCryptographic(byte[] cose, byte[] kid, AccessTokenConditions accessTokenConditions, VerificationResult verificationResult, List<ValidationStatusResponse.Result> results) {
        ZonedDateTime validationClock = ZonedDateTime.parse(accessTokenConditions.getValidationClock());
        String kidBase64 = Base64.getEncoder().encodeToString(kid);
        List<Certificate> certificates = signerInformationService.getCertificates(kidBase64);
        if (certificates!=null && certificates.size()>0) {
            boolean signValidated = false;
            for (Certificate certificate : certificates) {
                cryptoService.validate(cose, certificate, verificationResult);
                if (verificationResult.getCoseVerified()) {
                    ZonedDateTime expirationTime = (certificate instanceof X509Certificate) ?
                            ((X509Certificate) certificate).getNotAfter().toInstant().atZone(DateTimeKt.getUTC_ZONE_ID())
                            : null;
                    if (expirationTime != null && validationClock.isAfter(expirationTime)) {
                        addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                                ValidationStatusResponse.Result.Type.FAILED, "cryptographic", "certificate expired for validation clock");
                    }
                    signValidated = true;
                    break;
                }
            }
            if (!signValidated) {
                addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                        ValidationStatusResponse.Result.Type.FAILED, "cryptographic", "signature invalid");
            } else {
                addResult(results, ValidationStatusResponse.Result.ResultType.OK,
                        ValidationStatusResponse.Result.Type.PASSED, "cryptographic", "signature valid");
            }
        } else {
            addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                    ValidationStatusResponse.Result.Type.FAILED, "cryptographic", "unknown dcc signing kid");
        }
    }

    private void validateGreenCertificateData(GreenCertificateData greenCertificateData, AccessTokenConditions accessTokenConditions, List<ValidationStatusResponse.Result> results) {
        if (greenCertificateData.getGreenCertificate().getPerson().getStandardisedFamilyName()==null ||
        !greenCertificateData.getGreenCertificate().getPerson().getStandardisedFamilyName().equals(accessTokenConditions.getFnt())) {
            addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                    ValidationStatusResponse.Result.Type.FAILED,"Data check","family name does not match");
        }
        if (greenCertificateData.getGreenCertificate().getPerson().getStandardisedGivenName()==null ||
                !greenCertificateData.getGreenCertificate().getPerson().getStandardisedGivenName().equals(accessTokenConditions.getGnt())) {
            addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                    ValidationStatusResponse.Result.Type.FAILED,"Data check","given name does not match");
        }
        if (greenCertificateData.getGreenCertificate().getDateOfBirth()==null ||
                !greenCertificateData.getGreenCertificate().getDateOfBirth().equals(accessTokenConditions.getDob())) {
            addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                    ValidationStatusResponse.Result.Type.FAILED,"Data check","data of birth does not match");
        }
        String certTypeSymbol;
        switch (greenCertificateData.getGreenCertificate().getType()) {
            case RECOVERY:
                certTypeSymbol = "r";
                break;
            case TEST:
                certTypeSymbol = "t";
                break;
            case VACCINATION:
                certTypeSymbol = "v";
                break;
            default:
                throw new DccException("unsupported cert type");
        }
        if (accessTokenConditions.getType()!=null) {
            if (!Arrays.asList(accessTokenConditions.getType()).contains(certTypeSymbol)) {
                addResult(results, ValidationStatusResponse.Result.ResultType.NOK,
                      ValidationStatusResponse.Result.Type.FAILED,"cert type","required cert type not provided");
            }
        }
    }

    private void addResult(List<ValidationStatusResponse.Result> results, ValidationStatusResponse.Result.ResultType resultType,
                      ValidationStatusResponse.Result.Type type, String identifier, String details) {
        ValidationStatusResponse.Result result = new ValidationStatusResponse.Result();
        result.setResult(resultType);
        result.setType(type);
        result.setIdentifier(identifier);
        result.setDetails(details);
        results.add(result);
    }
}
