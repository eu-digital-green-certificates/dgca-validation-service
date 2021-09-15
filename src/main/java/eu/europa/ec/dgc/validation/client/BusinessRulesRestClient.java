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

import eu.europa.ec.dgc.validation.client.dto.RulesResponseDto;
import java.util.List;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.context.annotation.Profile;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@Profile("pse")
@FeignClient(
    name = "business-download-client",
    url = "${dgc.businessRulesDownload.endpoint}",
    configuration = BusinessRulesRestClientConfig.class
)
public interface BusinessRulesRestClient {
    /**
        * Gets the trusted certificates from digital green certificate gateway.
     *
        * @return List of trustListItems
     */
    @GetMapping(value = "/rules", produces = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<List<RulesResponseDto>> getBusinessRulesList();

    @GetMapping(value = "/rules/{country}/{hash}", produces = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<String> getBusinessRulesItem(@PathVariable("country") String country, @PathVariable("hash") String hash);
}

