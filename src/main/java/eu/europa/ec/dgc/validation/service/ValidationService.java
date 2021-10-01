package eu.europa.ec.dgc.validation.service;

import com.nimbusds.jose.jwk.KeyUse;
import eu.europa.ec.dgc.validation.config.DgcConfigProperties;
import eu.europa.ec.dgc.validation.cryptschemas.EncryptedData;
import eu.europa.ec.dgc.validation.entity.ValidationInquiry;
import eu.europa.ec.dgc.validation.exception.DccException;
import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenConditions;
import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenPayload;
import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenType;
import eu.europa.ec.dgc.validation.restapi.dto.DccValidationRequest;
import eu.europa.ec.dgc.validation.restapi.dto.IdentityResponse;
import eu.europa.ec.dgc.validation.restapi.dto.PublicKeyJwk;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationInitRequest;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationInitResponse;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationStatusResponse;
import eu.europa.ec.dgc.validation.service.impl.FixAccessTokenKeyProvider;
import eu.europa.ec.dgc.validation.token.AccessTokenParser;
import eu.europa.ec.dgc.validation.token.ResultTokenBuilder;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

@Component
@Slf4j
@RequiredArgsConstructor
public class ValidationService {
    private static final String TOKEN_PREFIX = "Bearer ";
    private final ValidationStoreService validationStoreService;
    private final DgcConfigProperties dgcConfigProperties;
    private final KeyProvider keyProvider;
    private final DccValidator dccValidator;
    private final AccessTokenParser accessTokenParser;
    private final DccCryptService dccCryptService;
    private final DccSign dccSign;
    private final AccessTokenKeyProvider accessTokenKeyProvider;
    private final TokenBlackListService tokenBlackListService;
    private final ResultCallbackService resultCallbackService;
    private final IdentityService identityService;

    /**
     * validate Access Token.
     * @param audience audience
     * @param subject subject
     * @param accessTokenCompact accessTokenCompact
     * @return payload or null if validation failed
     */
    public AccessTokenPayload validateAccessToken(String audience, String subject, String accessTokenCompact) {
        if (accessTokenCompact != null && accessTokenCompact.startsWith(TOKEN_PREFIX)) {
            String plainToken = accessTokenCompact.substring(TOKEN_PREFIX.length());
            
            Jwt token = accessTokenParser.extractPayload(plainToken);

            String kid = (String) token.getHeader().get("kid");

            if (kid == null) {
                log.warn("revoke access token: kid was not found");
                return null;
            }

            String alg = (String) token.getHeader().get("alg");

            switch (alg) {
                case "RS256":
                case "ES256":
                case "PS256":
                    break;
                default: {
                    log.warn("revoke access token: unsupported algorithm");
                    return null;
                }
            }
            
            Claims claims = (Claims) token.getBody();

            if (claims.containsKey("exp")
                && claims.getExpiration().toInstant().getEpochSecond() < Instant.now().getEpochSecond()) {
                log.warn("revoke access token: expired");
                return null;
            }

            if (claims.containsKey("iat")
                && claims.getIssuedAt().toInstant().getEpochSecond() > Instant.now().getEpochSecond()) {
                log.warn("revoke access token: iat in the future");
                return null;
            }

            if (claims.containsKey("aud")
                && (claims.getAudience() == null || !claims.getAudience().equals(audience))) {
                log.warn("revoke access token: aud");
                return null;
            }

            if (claims.containsKey("sub") && !subject.equals(claims.getSubject())) {
                log.warn("revoke access token: sub mismatch");
                return null;
            }

            if (claims.containsKey("aud") && !claims.getAudience().equals(audience)) {
                log.debug("wrong audience");
                return null;
            }

            if (claims.containsKey("sub") && !claims.getSubject().equals(subject)) {
                log.debug("subject wrong");
                return null;
            }

            try {
                AccessTokenPayload accessToken = accessTokenParser.parseToken(
                    plainToken, accessTokenKeyProvider.getPublicKey(kid));
                return accessToken;
            } catch (Exception e) {
                log.warn("revoke access token: parsing",e);
                return null;
            }
        }
        return null;
    }

    /**
     * init validation.
     * @param validationInitRequest validationInitRequest
     * @param subject subject random string (uuid)
     * @return ValidationInitResponse
     */
    public ValidationInitResponse initValidation(ValidationInitRequest validationInitRequest, 
                                                 String subject, 
                                                 Boolean encryption, 
                                                 Boolean signature) {
        ValidationInquiry validationInquiry = new ValidationInquiry();
        validationInquiry.setValidationStatus(ValidationInquiry.ValidationStatus.OPEN);
        validationInquiry.setSubject(subject);
        validationInquiry.setPublicKey(validationInitRequest.getPubKey());
        validationInquiry.setKeyType(validationInitRequest.getKeyType());
        validationInquiry.setCallbackUrl(validationInitRequest.getCallback());
        if (validationInitRequest.getNonce() != null) {
            validationInquiry.setNonce(Base64.getDecoder().decode(validationInitRequest.getNonce()));
        }
        long expirationTime = Instant.now().plusSeconds(dgcConfigProperties.getValidationExpire()).getEpochSecond();
        validationInquiry.setExp(expirationTime);
        validationStoreService.storeValidation(validationInquiry);
        
        ValidationInitResponse validationInitResponse = new ValidationInitResponse();
        IdentityResponse response = identityService.getIdentity(null, null);
        if (signature != null && signature.booleanValue()) {
            PublicKeyJwk result = response.getVerificationMethod().stream()
                                                                .filter(x -> x.getPublicKeyJwk()
                                                                              .getUse()
                                                                              .equals(KeyUse.SIGNATURE.toString()) 
                                                                             && 
                                                                             x.getId()
                                                                              .contains(dgcConfigProperties
                                                                                            .getActiveSignKey()))
                                                                .findFirst()
                                                                .get()
                                                                .getPublicKeyJwk();
            if (result != null) {
                validationInitResponse.setSigKey(result);
            }
        }

        if (encryption != null && encryption.booleanValue()) {
            PublicKeyJwk result = response.getVerificationMethod().stream()
                                                                .filter(x ->  x.getPublicKeyJwk()
                                                                               .getUse()
                                                                               .equals(KeyUse.ENCRYPTION.toString()))
                                                                .findAny()
                                                                .get()
                                                                .getPublicKeyJwk();
            if (result != null) {
                validationInitResponse.setEncKey(result);
            }
        }
   
        validationInitResponse.setExp(expirationTime);
        validationInitResponse.setSubject(subject);
        validationInitResponse.setAud(dgcConfigProperties.getServiceUrl() + "/validate/" + subject);

        return validationInitResponse;
    }

    private boolean checkMandatoryFields(AccessTokenPayload accessToken) {
        AccessTokenType tokenType = AccessTokenType.getTokenForInt(accessToken.getType());

        if (accessToken.getConditions() == null) {
            return false;
        }

        AccessTokenConditions conditions = accessToken.getConditions();

        if (conditions.getValidFrom() == null || conditions.getDob() == null
            || conditions.getValidTo() == null || conditions.getLang() == null || conditions.getType() == null) {
            return false;
        }

        if (tokenType == AccessTokenType.Structure && conditions.getHash() == null) {
            return false;
        }

        if (tokenType.intValue() > AccessTokenType.Structure.intValue()) {
            if (conditions.getFnt() == null
                || conditions.getGnt() == null
                || conditions.getValidationClock() == null) {
                return false;
            }

            if (tokenType == AccessTokenType.Full && (
                conditions.getRoa() == null
                    || conditions.getRod() == null
                    || conditions.getCoa() == null
                    || conditions.getCod() == null)) {
                return false;
            }
        }

        return true;
    }

    /**
     * validate.
     * @param dccValidationRequest dccValidationRequest
     * @param accessToken accessToken
     * @return token
     */
    public String validate(DccValidationRequest dccValidationRequest, AccessTokenPayload accessToken) {
        String subject = accessToken.getSub();
        ValidationInquiry validationInquiry = validationStoreService.receiveValidation(subject);
        String resultToken;
        ResultTokenBuilder resultTokenBuilder = new ResultTokenBuilder();
        if (validationInquiry != null) {
            if (!tokenBlackListService.checkPutBlacklist(accessToken.getJti(), accessToken.getExp())) {
                throw new DccException("token identifier jti already used", HttpStatus.GONE.value());
            }

            if (!checkMandatoryFields(accessToken)) {
                throw new DccException("Validation Conditions missing or not properly set",
                    HttpStatus.BAD_REQUEST.value());
            }

            if (!checkSignature(dccValidationRequest.getSigAlg(),
                org.bouncycastle.util.encoders.Base64.decode(dccValidationRequest.getDcc()),
                org.bouncycastle.util.encoders.Base64.decode(dccValidationRequest.getSig()),
                validationInquiry.getPublicKey())) {
                throw new DccException("invalid signature", HttpStatus.UNPROCESSABLE_ENTITY.value());
            }
            String dcc = decodeDcc(dccValidationRequest, validationInquiry);


            List<ValidationStatusResponse.Result> results = dccValidator.validate(
                dcc, accessToken.getConditions(), AccessTokenType.getTokenForInt(accessToken.getType()), false);
            resultToken = resultTokenBuilder.build(results, accessToken.getSub(),
                dgcConfigProperties.getServiceUrl(),
                accessToken.getConditions().getCategory(),
                Date.from(Instant.now().plusSeconds(dgcConfigProperties.getConfirmationExpire())),
                keyProvider.receivePrivateKey(keyProvider.getActiveSignKey()),
                keyProvider.getKid(keyProvider.getActiveSignKey()));
            validationInquiry.setValidationResult(resultToken);
            validationInquiry.setValidationStatus(ValidationInquiry.ValidationStatus.READY);
            validationStoreService.updateValidation(validationInquiry);
        } else {
            resultToken = resultTokenBuilder.build(null, accessToken.getSub(), 
                dgcConfigProperties.getServiceUrl(),
                accessToken.getConditions().getCategory(),
                Date.from(Instant.now().plusSeconds(dgcConfigProperties.getConfirmationExpire())),
                keyProvider.receivePrivateKey(keyProvider.getActiveSignKey()),
                keyProvider.getKid(keyProvider.getActiveSignKey()));
        }
        if (validationInquiry.getCallbackUrl() != null && validationInquiry.getCallbackUrl().length() > 0
                && resultToken != null) {
            resultCallbackService.scheduleCallback(validationInquiry.getCallbackUrl(), resultToken);
        }
        return resultToken;
    }

    private boolean checkSignature(String sigAlg, byte[] data, byte[] signature, String publicKeyBase64) {
        try {
            if (!sigAlg.contains("ECDSA") && !sigAlg.contains("RSA")) {
                return false;
            }

            sigAlg = sigAlg.contains("ECDSA") ? "EC" : "RSA";

            byte[] keyBytes = Base64.getDecoder().decode(cleanKeyString(publicKeyBase64));
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance(sigAlg);
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
            keyProvider.receivePrivateKey(keyProvider.getKeyName(dccValidationRequest.getKid())),
            dccValidationRequest.getEncScheme(), validationInquiry.getNonce()), StandardCharsets.UTF_8);
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
