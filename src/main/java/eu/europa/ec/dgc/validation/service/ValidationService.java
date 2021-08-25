package eu.europa.ec.dgc.validation.service;

import eu.europa.ec.dgc.validation.config.DgcConfigProperties;
import eu.europa.ec.dgc.validation.entity.KeyType;
import eu.europa.ec.dgc.validation.entity.ValidationInquiry;
import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenPayload;
import eu.europa.ec.dgc.validation.restapi.dto.DccValidationRequest;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationInitRequest;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationInitResponse;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationStatusResponse;
import eu.europa.ec.dgc.validation.token.AccessTokenParser;
import eu.europa.ec.dgc.validation.token.ResultTokenBuilder;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.impl.DefaultClaims;
import io.jsonwebtoken.impl.DefaultJwt;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalUnit;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Component
@Slf4j
@RequiredArgsConstructor
public class ValidationService {
    private final ValidationStoreService validationStoreService;
    private final DgcConfigProperties dgcConfigProperties;
    private final KeyProvider keyProvider;
    private final DccValidator dccValidator;
    private final AccessTokenParser accessTokenParser;

    public ValidationInitResponse initValidation(ValidationInitRequest validationInitRequest) {
        ValidationInquiry validationInquiry = new ValidationInquiry();
        validationInquiry.setValidationStatus(ValidationInquiry.ValidationStatus.OPEN);
        validationInquiry.setSubject(validationInitRequest.getSubject());
        validationInquiry.setPublicKey(validationInitRequest.getPubKey());
        validationInquiry.setKeyType(validationInitRequest.getKeyType());
        long timeNow = Instant.now().getEpochSecond();
        long expirationTime = timeNow + dgcConfigProperties.getValidationExpire().get(ChronoUnit.SECONDS);
        validationInquiry.setExp(expirationTime);

        validationStoreService.storeValidation(validationInquiry, expirationTime);
        ValidationInitResponse validationInitResponse = new ValidationInitResponse();
        validationInitResponse.setExp(expirationTime);
        validationInitResponse.setSubject(validationInitRequest.getSubject());
        validationInitResponse.setAud(dgcConfigProperties.getServiceUrl()+"/validate");

        return validationInitResponse;
    }

    public String validate(DccValidationRequest dccValidationRequest, String accessTokenCompact) {
        AccessTokenPayload accessToken = accessTokenParser.parseToken(accessTokenCompact);
        String subject = accessToken.getSub();
        ValidationInquiry validationInquiry = validationStoreService.receiveValidation(subject);
        String resultToken;
        if (validationInquiry!=null) {
            String dcc = decodeDcc(dccValidationRequest, validationInquiry);
            ResultTokenBuilder resultTokenBuilder = new ResultTokenBuilder();
            List<ValidationStatusResponse.Result> results = dccValidator.validate(dcc, accessToken.getConditions());
            resultTokenBuilder.results(results);
            resultToken  = resultTokenBuilder.build(keyProvider.receivePrivateKey(KeyType.ValidationServiceSignKey),
                    keyProvider.getKid(KeyType.ValidationServiceSignKey));
            validationInquiry.setValidationResult(resultToken);
            validationInquiry.setValidationStatus(ValidationInquiry.ValidationStatus.READY);
            validationStoreService.updateValidation(validationInquiry);
        } else {
            resultToken  = null;
        }
        return resultToken;
    }

    private String decodeDcc(DccValidationRequest dccValidationRequest, ValidationInquiry validationInquiry) {
        return null;
    }
}
