package eu.europa.ec.dgc.validation.service;

import eu.europa.ec.dgc.validation.config.DgcConfigProperties;
import eu.europa.ec.dgc.validation.cryptschemas.CryptSchemaIdentity;
import eu.europa.ec.dgc.validation.entity.KeyType;
import eu.europa.ec.dgc.validation.exception.DccException;
import eu.europa.ec.dgc.validation.restapi.dto.IdentityResponse;
import eu.europa.ec.dgc.validation.restapi.dto.PublicKeyJwk;
import eu.europa.ec.dgc.validation.restapi.dto.VerificationMethod;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Component
@Slf4j
@RequiredArgsConstructor
public class IdentityService {
    private final DgcConfigProperties dgcConfigProperties;
    private final KeyProvider keyProvider;

    private static final String ELEMENT_VERIFICATION_METHOD = "verificationMethod";
    private static final String VALIDATION_TYPE = "JsonWebKey2020";
    private static final String SCHEME_TYPE = "Scheme2021";
    /**
     * get identity.
     * @param element null or verificationMethod
     * @param type null or type (always JsonWebKey2020)
     * @return identity document
     */
    public IdentityResponse getIdentity(final String element, final String type) {
        IdentityResponse identityResponse = new IdentityResponse();
        String identityId = dgcConfigProperties.getServiceUrl() + "/identity";
        identityResponse.setId(identityId);
        List<VerificationMethod> verificationMethods = new ArrayList<>();
        identityResponse.setVerificationMethod(verificationMethods);
        if ((element == null || ELEMENT_VERIFICATION_METHOD.equals(element))
            && (type == null || VALIDATION_TYPE.equals(type))) {
            for (String keyName : keyProvider.getKeyNames(KeyType.All)) {
                VerificationMethod verificationMethod = new VerificationMethod();
                verificationMethod.setId(identityId + "/verificationMethod/"+VALIDATION_TYPE+"#" + keyName);
                verificationMethod.setController(identityId);
                verificationMethod.setType(VALIDATION_TYPE);
                Certificate certificate = keyProvider.receiveCertificate(keyName);
                PublicKeyJwk publicKeyJwk = new PublicKeyJwk();
                try {
                    publicKeyJwk.setX5c(Base64.getEncoder().encodeToString(certificate.getEncoded()));
                    publicKeyJwk.setKid(keyProvider.getKid(keyName));
                    publicKeyJwk.setAlg(keyProvider.getAlg(keyName));
                    publicKeyJwk.setUse(keyProvider.getKeyUse(keyName).toString());
                } catch (CertificateEncodingException e) {
                    throw new DccException("can not encode certificate", e);
                }
                verificationMethod.setPublicKeyJwk(publicKeyJwk);
                verificationMethods.add(verificationMethod);
            }
            
            for (String schema : CryptSchemaIdentity.GetCryptSchemes()) {

                VerificationMethod verificationMethod = new VerificationMethod();
                verificationMethod
                    .setId(identityId + "/verificationMethod/"+SCHEME_TYPE+"#ValidationServiceEncScheme-" + schema);
                verificationMethod.setController(identityId);
                verificationMethod.setType(SCHEME_TYPE);
                final boolean rsa = !schema.startsWith("EC");
                ArrayList<String> ids = new ArrayList<String>();
                for (VerificationMethod vm : verificationMethods
                                                .stream()
                                                .filter(x -> 
                                                           x.getPublicKeyJwk() != null 
                                                        && 
                                                           x.getPublicKeyJwk().getUse() == "enc" 
                                                        && 
                                                        (
                                                            (!rsa && x.getPublicKeyJwk().getAlg().startsWith("ES"))
                                                        ||
                                                            (rsa && !x.getPublicKeyJwk().getAlg().startsWith("ES"))
                                                        )
                                                        )
                                                .collect(Collectors.toList()))
                {
                    ids.add(vm.getId());
                }
                verificationMethod.setVerificationMethods(ids.toArray(new String[0]));
                verificationMethods.add(verificationMethod);
            }

        }
        return identityResponse;
    }
}
