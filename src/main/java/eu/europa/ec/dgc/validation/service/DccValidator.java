package eu.europa.ec.dgc.validation.service;

import dgca.verifier.app.decoder.base45.Base45Service;
import dgca.verifier.app.decoder.base45.DefaultBase45Service;
import dgca.verifier.app.decoder.cbor.CborService;
import dgca.verifier.app.decoder.cbor.DefaultCborService;
import dgca.verifier.app.decoder.cbor.GreenCertificateData;
import dgca.verifier.app.decoder.compression.CompressorService;
import dgca.verifier.app.decoder.compression.DefaultCompressorService;
import dgca.verifier.app.decoder.cose.CoseService;
import dgca.verifier.app.decoder.cose.DefaultCoseService;
import dgca.verifier.app.decoder.model.CoseData;
import dgca.verifier.app.decoder.model.VerificationResult;
import dgca.verifier.app.decoder.prefixvalidation.DefaultPrefixValidationService;
import dgca.verifier.app.decoder.prefixvalidation.PrefixValidationService;
import dgca.verifier.app.decoder.schema.DefaultSchemaValidator;
import dgca.verifier.app.decoder.schema.SchemaValidator;
import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenConditions;
import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenType;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationStatusResponse;
import java.util.ArrayList;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
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
        validateGreenCertificateData(greenCertificateData, results);
        if (accessTokenType.intValue()>AccessTokenType.Structure.intValue()) {
            validateCryptograpic(cose, coseData.getKid(), verificationResult, results);
            if (accessTokenType==AccessTokenType.Full) {
                validateRules(greenCertificateData, verificationResult, results);
            }
        }
        if (results.isEmpty()) {
            addResult(results, ValidationStatusResponse.Result.ResultType.OK,
                    ValidationStatusResponse.Result.Type.PASSED, "OK", "OK");
        }

        return results;
    }

    private void validateRules(GreenCertificateData greenCertificateData, VerificationResult verificationResult, List<ValidationStatusResponse.Result> results) {
        // TODO add certlogic validation here
    }

    private void validateCryptograpic(byte[] cose, byte[] kid, VerificationResult verificationResult, List<ValidationStatusResponse.Result> results) {
        // TODO implement signarure validation here
    }

    private void validateGreenCertificateData(GreenCertificateData greenCertificateData, List<ValidationStatusResponse.Result> results) {

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
