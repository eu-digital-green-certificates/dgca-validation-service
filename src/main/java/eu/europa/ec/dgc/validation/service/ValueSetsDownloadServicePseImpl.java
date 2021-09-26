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

import eu.europa.ec.dgc.validation.client.ValueSetsRestClient;
import eu.europa.ec.dgc.validation.client.dto.ValueSetResponseDto;
import eu.europa.ec.dgc.validation.model.ValueSetItem;
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
public class ValueSetsDownloadServicePseImpl implements ValueSetsDownloadService {

    private final ValueSetsRestClient valueSetsRestClient;
    private final ValueSetService valueSetService;

    @Override
    @Scheduled(fixedDelayString = "${dgc.valueSetsDownload.timeInterval}")
    @SchedulerLock(name = "GatewayDataDownloadService_downloadValueSets", lockAtLeastFor = "PT0S",
        lockAtMostFor = "${dgc.valueSetsDownload.lockLimit}")
    public void downloadValueSets() {

        ResponseEntity<List<ValueSetResponseDto>> responseEntity;

        try {
            responseEntity = valueSetsRestClient.getValueSetsList();
        } catch (FeignException e) {
            log.error("Download of value sets failed with exception. Service responded with status code: {}",
                e.status());
            return;
        }

        List<ValueSetResponseDto> valueSetsList = responseEntity.getBody();
        if (responseEntity.getStatusCode() != HttpStatus.OK || valueSetsList == null) {
            log.error("Download of value sets failed. Service responded with status code: {}",
                responseEntity.getStatusCode());
            return;
        }

        log.info("Got Response from Service, Value sets index contains sets: {}", valueSetsList.size());

        List<ValueSetItem> items = getValueSetItem(valueSetsList);

        if (!items.isEmpty()) {
            valueSetService.updateValueSets(items);
        } else {
            log.warn("The download of the bvalue sets seems to fail, as the download connector "
                + "returns an empty list. No data will be changed.");
        }

        log.info("Download finished, Downloaded value sets: {}", items.size());

    }

    private List<ValueSetItem> getValueSetItem(List<ValueSetResponseDto> valueSetsList) {

        List<ValueSetItem> items = new ArrayList<>();

        for (ValueSetResponseDto valueSetIndex : valueSetsList) {
            ValueSetItem item = getValueSetData(valueSetIndex);
            if (item != null) {
                items.add(item);
            }
        }
        return items;
    }

    private ValueSetItem getValueSetData(ValueSetResponseDto valueSetIndex) {
        ResponseEntity<String> responseEntity;

        try {
            responseEntity = valueSetsRestClient.getValueSetData(valueSetIndex.getHash());
        } catch (FeignException e) {
            log.error("Download of value set item failed with exception. Service responded with status code: {}",
                e.status());
            return null;
        }

        String rawData = responseEntity.getBody();

        if (responseEntity.getStatusCode() != HttpStatus.OK || rawData == null) {
            log.error("Download of value set item failed. Service responded with status code: {}",
                responseEntity.getStatusCode());
            return null;
        }
        ValueSetItem item = new ValueSetItem();
        item.setId(valueSetIndex.getId());
        item.setHash(valueSetIndex.getHash());
        item.setRawData(rawData);

        return item;
    }
}
