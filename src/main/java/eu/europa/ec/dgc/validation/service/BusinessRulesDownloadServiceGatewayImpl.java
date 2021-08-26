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



import eu.europa.ec.dgc.gateway.connector.DgcGatewayValidationRuleDownloadConnector;
import eu.europa.ec.dgc.validation.model.BusinessRuleItem;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Profile;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;


/**
 * A service to download the valuesets, business rules and country list from the digital covid certificate gateway.
 */
@Slf4j
@RequiredArgsConstructor
@Component
@ConditionalOnProperty("dgc.gateway.connector.enabled")
@Profile("!btp")
public class BusinessRulesDownloadServiceGatewayImpl implements BusinessRulesDownloadService {

    private final DgcGatewayValidationRuleDownloadConnector dgcRuleConnector;

    private final BusinessRuleService businessRuleService;

    @Override
    @Scheduled(fixedDelayString = "${dgc.businessRulesDownload.timeInterval}")
    @SchedulerLock(name = "GatewayDataDownloadService_downloadBusinessRules", lockAtLeastFor = "PT0S",
        lockAtMostFor = "${dgc.businessRulesDownload.lockLimit}")
    public void downloadBusinessRules() {
        List<BusinessRuleItem> ruleItems;

        log.info("Business rules download started");

        try {
            ruleItems = businessRuleService.createBusinessRuleItemList(dgcRuleConnector.getValidationRules().flat());
        } catch (NoSuchAlgorithmException e) {
            log.error("Failed to hash business rules on download.",e);
            return;
        }

        if (!ruleItems.isEmpty()) {
            businessRuleService.updateBusinessRules(ruleItems);
        } else {
            log.warn("The download of the business rules seems to fail, as the download connector "
                + "returns an empty business rules list.-> No data was changed.");
        }

        log.info("Business rules finished");
    }

}
