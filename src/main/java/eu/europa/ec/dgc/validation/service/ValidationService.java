package eu.europa.ec.dgc.validation.service;

import eu.europa.ec.dgc.validation.config.DgcConfigProperties;
import eu.europa.ec.dgc.validation.cryptschemas.EncryptedData;
import eu.europa.ec.dgc.validation.entity.KeyType;
import eu.europa.ec.dgc.validation.entity.ValidationInquiry;
import eu.europa.ec.dgc.validation.exception.DccException;
import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenConditions;
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

import com.fasterxml.jackson.annotation.JsonProperty.Access;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.joda.time.DateTime;
import org.springframework.http.HttpStatus;
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
    private final DccCryptService dccCryptService;
    private final DccSign dccSign;
    private final FixAccessTokenKeyProvider accessTokenKeyProvider;
    private final TokenBlackListService tokenBlackListService;

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
        validationStoreService.storeValidation(validationInquiry);

        ValidationInitResponse validationInitResponse = new ValidationInitResponse();
        validationInitResponse.setExp(expirationTime);
        validationInitResponse.setSubject(validationInitRequest.getSubject());
        validationInitResponse.setAud(dgcConfigProperties.getServiceUrl()+"/validate");

        return validationInitResponse;
    }

    private boolean checkMandatoryFields(AccessTokenPayload accessToken)
    {
        AccessTokenType tokenType= AccessTokenType.getTokenForInt(accessToken.getType());

        if(accessToken.getExp()<Instant.now().getEpochSecond())
            return false;

        if(accessToken.getIat()>Instant.now().getEpochSecond())
            return false;

        if(accessToken.getConditions()==null)
            return false;

        AccessTokenConditions conditions = accessToken.getConditions();

        if(conditions.getValidFrom()==null || conditions.getDob()==null|| conditions.getValidTo()==null|| conditions.getLang()==null || conditions.getType()==null)
            return false;

        if(tokenType == AccessTokenType.Structure && conditions.getHash()==null)
            return false;
         
        if(tokenType.intValue()>AccessTokenType.Structure.intValue())
        {
            if(conditions.getFnt()==null ||
               conditions.getGnt()==null||
               conditions.getValidationClock()==null)
                return false;

            if(tokenType == AccessTokenType.Full && (
                conditions.getRoa() == null ||
                conditions.getRod() == null ||
                conditions.getCoa() == null ||
                conditions.getCod() == null))
                return false;
        }

        return true;
    }

    public String validate(DccValidationRequest dccValidationRequest, String accessTokenCompact) {
        String kid = accessTokenParser.extractKid(accessTokenCompact);
        AccessTokenPayload accessToken = accessTokenParser.parseToken(accessTokenCompact, accessTokenKeyProvider.getPublicKey(kid));
        String subject = accessToken.getSub();
        ValidationInquiry validationInquiry = validationStoreService.receiveValidation(subject);
        String resultToken;
        if (validationInquiry!=null) {
            if (!tokenBlackListService.checkPutBlacklist(accessToken.getJti(), accessToken.getExp())) {
                throw new DccException("token identifier jti already used", HttpStatus.GONE.value());
            }

            if(!checkMandatoryFields(accessToken))
                throw new DccException("Validation Conditions missing or not properly set",HttpStatus.BAD_REQUEST.value());

            if (!checkSignature(org.bouncycastle.util.encoders.Base64.decode(dccValidationRequest.getDcc()),
                                org.bouncycastle.util.encoders.Base64.decode(dccValidationRequest.getSig()),
                                validationInquiry.getPublicKey())) {
                throw new DccException("invalid signature", HttpStatus.UNPROCESSABLE_ENTITY.value());
            }
            String dcc = decodeDcc(dccValidationRequest, validationInquiry);

            ResultTokenBuilder resultTokenBuilder = new ResultTokenBuilder();
            List<ValidationStatusResponse.Result> results = dccValidator.validate(dcc, accessToken.getConditions(), AccessTokenType.getTokenForInt(accessToken.getType()));
            resultTokenBuilder.results(results);
            resultToken  = resultTokenBuilder.build(keyProvider.receivePrivateKey(keyProvider.getActiveSignKey()),dccValidationRequest.getKid());
            validationInquiry.setValidationResult(resultToken);
            validationInquiry.setValidationStatus(ValidationInquiry.ValidationStatus.READY);
            validationStoreService.updateValidation(validationInquiry);
        } else {
            resultToken  = null;
        }
        return resultToken;
    }

    private boolean checkSignature(byte[] data, byte[] signature, String publicKeyBase64) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(cleanKeyString(publicKeyBase64));
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("EC");
            PublicKey publicKey = kf.generatePublic(spec);
            return dccSign.verifySignature(data, signature, publicKey);
        } catch (Exception e) {
            return false;
        }
    }

    private String decodeDcc(DccValidationRequest dccValidationRequest, ValidationInquiry validationInquiry) {
        EncryptedData encryptedData = new EncryptedData();
        encryptedData.setDataEncrypted(Base64.getDecoder().decode(dccValidationRequest.getDcc()));
        encryptedData.setEncKey(Base64.getDecoder().decode(dccValidationRequest.getEncKey()));
        String dcc = new String(dccCryptService.decryptData(encryptedData,
                keyProvider.receivePrivateKey(keyProvider.getKeyName( dccValidationRequest.getKid())),
                dccValidationRequest.getEncScheme()),StandardCharsets.UTF_8);
        return dcc;
    }

    private String cleanKeyString(String rawKey) {
        return rawKey.replaceAll("\\n", "")
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "");
    }
}
