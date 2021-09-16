package eu.europa.ec.dgc.validation.service;

import eu.europa.ec.dgc.validation.config.DgcConfigProperties;
import eu.europa.ec.dgc.validation.entity.KeyType;
import eu.europa.ec.dgc.validation.entity.KeyUse;
import eu.europa.ec.dgc.validation.exception.DccException;
import eu.europa.ec.dgc.validation.restapi.dto.IdentityResponse;
import eu.europa.ec.dgc.validation.restapi.dto.PublicKeyJWK;
import eu.europa.ec.dgc.validation.restapi.dto.VerificationMethod;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Component
@Slf4j
@RequiredArgsConstructor
public class IdentityService {
    final private DgcConfigProperties dgcConfigProperties;
    final private KeyProvider keyProvider;

    public IdentityResponse getIdentity() {
        IdentityResponse identityResponse = new IdentityResponse();
        String identityId = dgcConfigProperties.getServiceUrl()+"/identity";
        identityResponse.setId(identityId);
        List<VerificationMethod> verificationMethods = new ArrayList<>();
        identityResponse.setVerificationMethod(verificationMethods);
        for (String keyName : keyProvider.getKeyNames(KeyType.All)) {
            VerificationMethod verificationMethod = new VerificationMethod();
            verificationMethod.setId(identityId+"/verificationMethod/JsonWebKey2020#"+keyName);
            verificationMethod.setController(identityId);
            verificationMethod.setType("JsonWebKey2020");
            Certificate certificate = keyProvider.receiveCertificate(keyName);
            PublicKeyJWK publicKeyJWK = new PublicKeyJWK();
            try {
                publicKeyJWK.setX5c(Base64.getEncoder().encodeToString(certificate.getEncoded()));
                publicKeyJWK.setKid(keyProvider.getKid(keyName));
                publicKeyJWK.setAlg(keyProvider.getAlg(keyName));
                publicKeyJWK.setUse(keyProvider.getKeyUse(keyName).toString());
            } catch (CertificateEncodingException e) {
                throw new DccException("can not encode certificate",e);
            }
            verificationMethod.setPublicKeyJWK(publicKeyJWK);
            verificationMethods.add(verificationMethod);
        }
        return identityResponse;
    }
}
