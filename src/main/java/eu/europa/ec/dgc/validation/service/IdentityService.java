package eu.europa.ec.dgc.validation.service;

import eu.europa.ec.dgc.validation.config.DgcConfigProperties;
import eu.europa.ec.dgc.validation.restapi.dto.IdentityResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Component
@Slf4j
@RequiredArgsConstructor
public class IdentityService {
    final private DgcConfigProperties dgcConfigProperties;

    public IdentityResponse getIdentity() {
        IdentityResponse identityResponse = new IdentityResponse();
        return identityResponse;
    }
}
