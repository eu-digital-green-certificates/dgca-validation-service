package eu.europa.ec.dgc.validation.service;

import eu.europa.ec.dgc.validation.restapi.dto.IdentityResponse;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@Slf4j
class IdentityServiceTest {
    @Autowired
    IdentityService identityService;

    @Test
    void testIdentity() throws Exception {
        IdentityResponse identity = identityService.getIdentity();
        assertNotNull(identity);
        assertEquals(2, identity.getVerificationMethod().size());
    }
}