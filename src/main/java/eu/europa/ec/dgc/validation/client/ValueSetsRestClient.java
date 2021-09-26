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

@Profile("pse")
@FeignClient(
    name = "valueset-download-client",
    url = "${dgc.valueSetsDownload.endpoint}",
    configuration = RestClientConfig.class
)
public interface ValueSetsRestClient {
    /**
     * Gets the value sets list from the business rule service.
     *
     * @return List of trustListItems
     */
    @GetMapping(value = "/valuesets", produces = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<List<ValueSetResponseDto>> getValueSetsList();

    /**
     * Gets the raw data of a value set from the business rule service.
     *
     * @param hash The hash value of the value set.
     * @return Raw value set data
     */
    @GetMapping(value = "/valuesets/{hash}", produces = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<String> getValueSetData(@PathVariable("hash") String hash);
}

