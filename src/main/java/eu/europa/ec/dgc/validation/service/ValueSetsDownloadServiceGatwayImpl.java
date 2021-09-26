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

import eu.europa.ec.dgc.gateway.connector.DgcGatewayValueSetDownloadConnector;
import eu.europa.ec.dgc.validation.model.ValueSetItem;
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
public class ValueSetsDownloadServiceGatwayImpl implements ValueSetsDownloadService {

    private final DgcGatewayValueSetDownloadConnector dgcValueSetConnector;

    private final ValueSetService valueSetService;

    @Override
    @Scheduled(fixedDelayString = "${dgc.valueSetsDownload.timeInterval}")
    @SchedulerLock(name = "GatewayDataDownloadService_downloadValueSets", lockAtLeastFor = "PT0S",
        lockAtMostFor = "${dgc.valueSetsDownload.lockLimit}")
    public void downloadValueSets() {
        List<ValueSetItem> valueSetItems;
        log.info("Valuesets download started");

        try {
            valueSetItems = valueSetService.createValueSetItemListFromMap(dgcValueSetConnector.getValueSets());
        } catch (NoSuchAlgorithmException e) {
            log.error("Failed to hash business rules on download.", e);
            return;
        }

        if (!valueSetItems.isEmpty()) {
            valueSetService.updateValueSets(valueSetItems);
        } else {
            log.warn("The download of the value sets seems to fail, as the download connector "
                + "returns an empty value sets list.-> No data was changed.");
        }

        log.info("Valuesets download finished");
    }

}
