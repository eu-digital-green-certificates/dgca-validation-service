/*-
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

package eu.europa.ec.dgc.validation.restapi.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Value;

@Schema(
    name = "BusinessRuleListItem",
    type = "object",
    example = "{"
        + "\"identifier\":\"VR-DE-1\","
        + "\"version\":\"1.0.0\","
        + "\"country\":\"DE\","
        + "\"hash\":\"6821d518570fe9f4417c482ff0d2582a7b6440f243a9034f812e0d71611b611f\""
        + "}"
)

@Value
public class BusinessRuleListItemDto {
    String identifier;
    String version;
    String country;
    String hash;
}
