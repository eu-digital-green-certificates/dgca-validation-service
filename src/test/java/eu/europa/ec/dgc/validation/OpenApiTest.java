package eu.europa.ec.dgc.validation;/*-
 * ---license-start
 * eu-digital-green-certificates / dgca-businessrule-service
 * ---
 * Copyright (C) 2021 T-Systems International GmbH and all other contributors
 * ---
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ---license-end
 */


import eu.europa.ec.dgc.gateway.connector.DgcGatewayCountryListDownloadConnector;
import eu.europa.ec.dgc.gateway.connector.DgcGatewayValidationRuleDownloadConnector;
import eu.europa.ec.dgc.gateway.connector.DgcGatewayValueSetDownloadConnector;
import java.io.BufferedInputStream;
import java.io.FileOutputStream;
import java.net.URL;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

@Slf4j
@SpringBootTest(
    properties = {
        "server.port=8080",
        "springdoc.api-docs.enabled=true",
        "springdoc.api-docs.path=/openapi"
    },
    webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT
)
class OpenApiTest {

    @MockBean
    DgcGatewayValidationRuleDownloadConnector dgcGatewayValidationRuleDownloadConnector;

    @MockBean
    DgcGatewayValueSetDownloadConnector dgcGatewayValueSetDownloadConnector;

    @MockBean
    DgcGatewayCountryListDownloadConnector dgcGatewayCountryListDownloadConnector;

    @Test
    void apiDocs() {
        try (BufferedInputStream in = new BufferedInputStream(new URL("http://localhost:8080/openapi").openStream());
            FileOutputStream out = new FileOutputStream("target/openapi.json")) {
            byte[] buffer = new byte[1024];
            int read;
            while ((read = in.read(buffer, 0, buffer.length)) != -1) {
                out.write(buffer, 0, read);
            }
        } catch (Exception e) {
            log.error("Failed to download openapi specification.", e);
            Assertions.fail();
        }
    }
}
