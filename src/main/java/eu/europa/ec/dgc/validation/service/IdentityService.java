package eu.europa.ec.dgc.validation.service;

import eu.europa.ec.dgc.validation.config.DgcConfigProperties;
import eu.europa.ec.dgc.validation.entity.KeyType;
import eu.europa.ec.dgc.validation.restapi.dto.IdentityResponse;
import eu.europa.ec.dgc.validation.restapi.dto.VerificationMethod;
import java.util.ArrayList;
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
        for (KeyType keyType : KeyType.values()) {
            VerificationMethod verificationMethod = new VerificationMethod();
            verificationMethod.setId(identityId+"#"+keyType.name()+"-1");
            verificationMethod.setController(identityId);
            verificationMethod.setPublicKeyJWK(null);
            verificationMethods.add(verificationMethod);
        }
        return identityResponse;
    }
}
