package eu.europa.ec.dgc.validation.service.impl;

import static org.junit.jupiter.api.Assertions.*;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;

class DynamicAccessTokenKeyProviderTest {
    @Test
    void loadKeysFromIdentityDoc() throws Exception {
        DynamicAccessTokenKeyProvider dynamicAccessTokenKeyProvider =
            new DynamicAccessTokenKeyProvider(null);

        InputStream inputStream = this.getClass().getResourceAsStream("/decorator-identity.json");
        String identityJson = IOUtils.toString(inputStream, StandardCharsets.UTF_8);

        dynamicAccessTokenKeyProvider.loadKeysFrom(identityJson);
        assertNotNull(dynamicAccessTokenKeyProvider.getPublicKey("bS8D2/Wz5tY="));

    }
}