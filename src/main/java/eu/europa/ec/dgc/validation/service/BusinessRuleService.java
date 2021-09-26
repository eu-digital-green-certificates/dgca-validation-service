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

package eu.europa.ec.dgc.validation.service;

import eu.europa.ec.dgc.gateway.connector.model.ValidationRule;
import eu.europa.ec.dgc.utils.CertificateUtils;
import eu.europa.ec.dgc.validation.entity.BusinessRuleEntity;
import eu.europa.ec.dgc.validation.model.BusinessRuleItem;
import eu.europa.ec.dgc.validation.repository.BusinessRuleRepository;
import eu.europa.ec.dgc.validation.restapi.dto.BusinessRuleListItemDto;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


@Slf4j
@RequiredArgsConstructor
@Service
public class BusinessRuleService {

    private final BusinessRuleRepository businessRuleRepository;

    private final CertificateUtils certificateUtils;

    /**
     * Gets list of all business rules ids and hashes.
     */
    public List<BusinessRuleListItemDto> getBusinessRulesList() {

        List<BusinessRuleListItemDto> rulesItems = businessRuleRepository.findAllByOrderByIdentifierAsc();
        return rulesItems;
    }


    /**
     * Gets list of all business rules ids and hashes for a country.
     */
    public List<BusinessRuleListItemDto> getBusinessRulesListForCountry(String country, String issuerCountry) {
        List<String> list = new ArrayList<String>();
        list.add(country.toUpperCase(Locale.ROOT));
        list.add(issuerCountry.toUpperCase(Locale.ROOT));
        List<BusinessRuleListItemDto> rulesItems =
            businessRuleRepository.findAllByCountryInOrderByIdentifierAsc(list);
        return rulesItems;
    }

    /**
     * f
     * Gets  a business rule by hash.
     */
    @Transactional
    public BusinessRuleEntity getBusinessRuleByCountryAndHash(String country, String hash) {

        return businessRuleRepository.findOneByCountryAndHash(country, hash);
    }

    /**
     * Updates the list of business rules.
     *
     * @param businessRules list of actual value sets
     */
    @Transactional
    public void updateBusinessRules(List<BusinessRuleItem> businessRules) {
        List<String> ruleHashes =
            businessRules.stream().map(BusinessRuleItem::getHash).collect(Collectors.toList());
        List<String> alreadyStoredRules = getBusinessRulesHashList();

        if (ruleHashes.isEmpty()) {
            businessRuleRepository.deleteAll();
        } else {
            businessRuleRepository.deleteByHashNotIn(ruleHashes);
        }

        for (BusinessRuleItem rule : businessRules) {
            if (!alreadyStoredRules.contains(rule.getHash())) {
                saveBusinessRule(rule);
            }
        }
    }

    /**
     * Saves a Business rule.
     *
     * @param rule The rule to be saved.
     */
    @Transactional
    public void saveBusinessRule(BusinessRuleItem rule) {
        BusinessRuleEntity bre = new BusinessRuleEntity();
        bre.setHash(rule.getHash());
        bre.setIdentifier(rule.getIdentifier());
        bre.setCountry(rule.getCountry().toUpperCase(Locale.ROOT));
        bre.setVersion(rule.getVersion());
        bre.setRawData(rule.getRawData());

        businessRuleRepository.save(bre);
    }

    /**
     * Creates a List of business rule items from a list of validation rules.
     *
     * @param validationRules the list containing the validation rules.
     * @return List of BusinessRuleItems.
     */
    public List<BusinessRuleItem> createBusinessRuleItemList(List<ValidationRule> validationRules)
        throws NoSuchAlgorithmException {
        List<BusinessRuleItem> businessRuleItems = new ArrayList<>();

        for (ValidationRule validationRule : validationRules) {
            BusinessRuleItem businessRuleItem = new BusinessRuleItem();

            businessRuleItem.setHash(certificateUtils.calculateHash(
                validationRule.getRawJson().getBytes(StandardCharsets.UTF_8)));
            businessRuleItem.setIdentifier(validationRule.getIdentifier());
            businessRuleItem.setCountry(validationRule.getCountry());
            businessRuleItem.setVersion(validationRule.getVersion());
            businessRuleItem.setRawData(validationRule.getRawJson());

            businessRuleItems.add(businessRuleItem);
        }

        return businessRuleItems;
    }


    /**
     * Gets a list of hash values of all stored business rules.
     *
     * @return List of hash values
     */
    private List<String> getBusinessRulesHashList() {
        return getBusinessRulesList().stream().map(BusinessRuleListItemDto::getHash).collect(Collectors.toList());
    }
}
