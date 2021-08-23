package eu.europa.ec.dgc.validation.service;

import eu.europa.ec.dgc.validation.config.DgcConfigProperties;
import eu.europa.ec.dgc.validation.entity.ValidationInquiry;
import eu.europa.ec.dgc.validation.restapi.dto.DccValidationRequest;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationInitRequest;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationInitResponse;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationStatusResponse;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.impl.DefaultClaims;
import io.jsonwebtoken.impl.DefaultJwt;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalUnit;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Component
@Slf4j
@RequiredArgsConstructor
public class ValidationService {
    private final ValidationStoreService validationStoreService;
    private final DgcConfigProperties dgcConfigProperties;

    public ValidationInitResponse initValidation(ValidationInitRequest validationInitRequest) {
        ValidationInquiry validationInquiry = new ValidationInquiry();
        validationInquiry.setSubject(validationInitRequest.getSubject());
        validationInquiry.setPublicKey(validationInitRequest.getPubKey());
        validationInquiry.setKeyType(validationInitRequest.getKeyType());
        long timeNow = Instant.now().getEpochSecond();
        long expirationTime = timeNow + dgcConfigProperties.getValidationExpire().get(ChronoUnit.SECONDS);
        validationInquiry.setExp(expirationTime);

        validationStoreService.storeValidation(validationInquiry);
        ValidationInitResponse validationInitResponse = new ValidationInitResponse();
        validationInitResponse.setExp(expirationTime);
        validationInitResponse.setSubject(validationInitRequest.getSubject());
        validationInitResponse.setAud("");

        return null;
    }

    public String validate(DccValidationRequest dccValidationRequest, String accessTokenCompact) {
        Jwt accessToken = Jwts.parser().parse(accessTokenCompact);
        DefaultClaims defaultClaims = (DefaultClaims) accessToken.getBody();
        String subject = defaultClaims.getSubject();
        ValidationInquiry validationInquiry = validationStoreService.receiveValidation(subject);
        if (validationInquiry!=null) {
            String dcc = decodeDcc(dccValidationRequest, validationInquiry);
        }

        return null;
    }

    private String decodeDcc(DccValidationRequest dccValidationRequest, ValidationInquiry validationInquiry) {
        return null;
    }
}
