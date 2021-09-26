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

package eu.europa.ec.dgc.validation.service;

import eu.europa.ec.dgc.validation.client.BusinessRulesRestClient;
import eu.europa.ec.dgc.validation.client.dto.RulesResponseDto;
import eu.europa.ec.dgc.validation.model.BusinessRuleItem;
import feign.FeignException;
import java.util.ArrayList;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Slf4j
@RequiredArgsConstructor
@Component
@Profile("pse")
public class BusinessRulesDownloadServicePseImpl implements BusinessRulesDownloadService {

    private final BusinessRulesRestClient businessRulesRestClient;
    private final BusinessRuleService businessRuleService;

    @Override
    @Scheduled(fixedDelayString = "${dgc.businessRulesDownload.timeInterval}")
    @SchedulerLock(name = "GatewayDataDownloadService_downloadBusinessRules", lockAtLeastFor = "PT0S",
        lockAtMostFor = "${dgc.businessRulesDownload.lockLimit}")
    public void downloadBusinessRules() {

        ResponseEntity<List<RulesResponseDto>> responseEntity;

        try {
            responseEntity = businessRulesRestClient.getBusinessRulesList();
        } catch (FeignException e) {
            log.error("Download of business rules failed with exception. Service responded with status code: {}",
                e.status());
            return;
        }

        List<RulesResponseDto> rulesList = responseEntity.getBody();
        if (responseEntity.getStatusCode() != HttpStatus.OK || rulesList == null) {
            log.error("Download of business rules failed. Service responded with status code: {}",
                responseEntity.getStatusCode());
            return;
        }

        log.info("Got Response from Service, Rule index contains rules: {}", rulesList.size());

        List<BusinessRuleItem> ruleItems = getRuleItems(rulesList);

        if (!ruleItems.isEmpty()) {
            businessRuleService.updateBusinessRules(ruleItems);
        } else {
            log.warn("The download of the business rules seems to fail, as the download connector "
                + "returns an empty list. No data will be changed.");
        }

        log.info("Download finished, Downloaded rules: {}", ruleItems.size());

    }

    private List<BusinessRuleItem> getRuleItems(List<RulesResponseDto> rulesList) {

        List<BusinessRuleItem> ruleItems = new ArrayList<>();

        for (RulesResponseDto ruleIndex : rulesList) {
            BusinessRuleItem item = getRuleData(ruleIndex);
            if (item != null) {
                ruleItems.add(item);
            }
        }

        return ruleItems;

    }

    private BusinessRuleItem getRuleData(RulesResponseDto ruleListItemDto) {
        ResponseEntity<String> responseEntity;

        try {
            responseEntity = businessRulesRestClient.getBusinessRulesItem(
                ruleListItemDto.getCountry(),
                ruleListItemDto.getHash());
        } catch (FeignException e) {
            log.error("Download of business rule item failed with exception. Service responded with status code: {}",
                e.status());
            return null;
        }

        String rawData = responseEntity.getBody();

        if (responseEntity.getStatusCode() != HttpStatus.OK || rawData == null) {
            log.error("Download of business rule item failed. Service responded with status code: {}",
                responseEntity.getStatusCode());
            return null;
        }

        BusinessRuleItem item = new BusinessRuleItem();
        item.setIdentifier(ruleListItemDto.getIdentifier());
        item.setCountry(ruleListItemDto.getCountry());
        item.setVersion((ruleListItemDto.getVersion()));
        item.setHash(ruleListItemDto.getHash());
        item.setRawData(rawData);

        return item;
    }
}
