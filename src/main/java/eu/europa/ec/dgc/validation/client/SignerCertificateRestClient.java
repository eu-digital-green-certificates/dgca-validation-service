/*-
 * ---license-start
 * eu-digital-green-certificates / dgca-validation-service
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

package eu.europa.ec.dgc.validation.client;

import eu.europa.ec.dgc.validation.client.dto.ValueSetResponseDto;
import java.util.List;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.context.annotation.Profile;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;

@Profile("pse")
@FeignClient(
    name = "signer-certificate-download-client",
    url = "${dgc.certificatesDownloader.endpoint}",
    configuration = RestClientConfig.class
)
public interface SignerCertificateRestClient {
    /**
     * Gets the kid list of all valid signer certificates.
     *
     * @return List of kids
     */
    @GetMapping(value = "/signercertificateStatus", produces = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<List<String>> getKidList();

    /**
     * Gets a signer certificate.
     *
     * @return signer certificate string
     */
    @GetMapping(value = "/signercertificateUpdate", produces = MediaType.TEXT_PLAIN_VALUE)
    ResponseEntity<String> getCertificate(@RequestHeader("X-RESUME-TOKEN") String resumeToken);

}

