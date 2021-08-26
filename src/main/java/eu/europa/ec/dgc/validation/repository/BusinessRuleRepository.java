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

package eu.europa.ec.dgc.validation.repository;

import eu.europa.ec.dgc.validation.entity.BusinessRuleEntity;
import eu.europa.ec.dgc.validation.restapi.dto.BusinessRuleListItemDto;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BusinessRuleRepository extends JpaRepository<BusinessRuleEntity, String> {

    List<BusinessRuleListItemDto> findAllByOrderByIdentifierAsc();

    List<BusinessRuleListItemDto> findAllByCountryOrderByIdentifierAsc(String country);

    BusinessRuleEntity findOneByCountryAndHash(String country, String hash);

    void deleteByHashNotIn(List<String> hashes);
}