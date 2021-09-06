package eu.europa.ec.dgc.validation.service;

import eu.europa.ec.dgc.validation.config.DgcConfigProperties;
import eu.europa.ec.dgc.validation.cryptschemas.EncryptedData;
import eu.europa.ec.dgc.validation.entity.KeyType;
import eu.europa.ec.dgc.validation.entity.ValidationInquiry;
import eu.europa.ec.dgc.validation.exception.DccException;
import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenPayload;
import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenType;
import eu.europa.ec.dgc.validation.restapi.dto.DccValidationRequest;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationInitRequest;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationInitResponse;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationStatusResponse;
import eu.europa.ec.dgc.validation.service.impl.FixAccessTokenKeyProvider;
import eu.europa.ec.dgc.validation.service.impl.MemoryTokenBlackListService;
import eu.europa.ec.dgc.validation.service.impl.MemoryValidationStoreService;
import eu.europa.ec.dgc.validation.token.AccessTokenParser;
import eu.europa.ec.dgc.validation.token.ResultTokenBuilder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

@Component
@Slf4j
@RequiredArgsConstructor
public class ValidationService {
    private final MemoryValidationStoreService validationStoreService;
    private final DgcConfigProperties dgcConfigProperties;
    private final KeyProvider keyProvider;
    private final DccValidator dccValidator;
    private final AccessTokenParser accessTokenParser;
    private final DccCryptService dccCryptService;
    private final DccSign dccSign;
    private final FixAccessTokenKeyProvider accessTokenKeyProvider;
    private final MemoryTokenBlackListService tokenBlackListService;

    public ValidationInitResponse initValidation(ValidationInitRequest validationInitRequest) {
        ValidationInquiry validationInquiry = new ValidationInquiry();
        validationInquiry.setValidationStatus(ValidationInquiry.ValidationStatus.OPEN);
        validationInquiry.setSubject(validationInitRequest.getSubject());
        validationInquiry.setPublicKey(validationInitRequest.getPubKey());
        validationInquiry.setKeyType(validationInitRequest.getKeyType());
        validationInquiry.setCallbackUrl(validationInitRequest.getCallback());
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
        AccessTokenPayload accessToken = accessTokenParser.parseToken(accessTokenCompact, accessTokenKeyProvider.getPublicKey("TODO","TODO"));
        String subject = accessToken.getSub();
        ValidationInquiry validationInquiry = validationStoreService.receiveValidation(subject);
        String resultToken;
        if (validationInquiry!=null) {
            if (!tokenBlackListService.checkPutBlacklist(accessToken.getJti())) {
                throw new DccException("token identifier jti already used", HttpStatus.GONE.value());
            }
            String dcc = decodeDcc(dccValidationRequest, validationInquiry);
            if (!checkSignature(dcc,dccValidationRequest,validationInquiry.getPublicKey())) {
                throw new DccException("invalid signature", HttpStatus.UNPROCESSABLE_ENTITY.value());
            }
            ResultTokenBuilder resultTokenBuilder = new ResultTokenBuilder();
            List<ValidationStatusResponse.Result> results = dccValidator.validate(dcc, accessToken.getConditions(), AccessTokenType.getTokenForInt(accessToken.getType()));
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

    private boolean checkSignature(String dcc, DccValidationRequest dccValidationRequest, String publicKeyBase64) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(publicKeyBase64);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("EC");
            PublicKey publicKey = kf.generatePublic(spec);
            return dccSign.verifySignature(dcc, dccValidationRequest.getSig(), publicKey);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new DccException("can not initialize signature validation",e);
        }
    }

    private String decodeDcc(DccValidationRequest dccValidationRequest, ValidationInquiry validationInquiry) {
        EncryptedData encryptedData = new EncryptedData();
        encryptedData.setDataEncrypted(Base64.getDecoder().decode(dccValidationRequest.getDcc()));
        encryptedData.setEncKey(Base64.getDecoder().decode(dccValidationRequest.getEncKey()));
        String dcc = new String(dccCryptService.decryptData(encryptedData,
                keyProvider.receivePrivateKey(KeyType.ValidationServiceEncKey),
                dccValidationRequest.getEncScheme()),StandardCharsets.UTF_8);
        return dcc;
    }
}
