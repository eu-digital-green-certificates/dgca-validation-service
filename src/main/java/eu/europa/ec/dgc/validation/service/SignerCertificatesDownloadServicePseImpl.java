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

import eu.europa.ec.dgc.gateway.connector.model.TrustListItem;
import eu.europa.ec.dgc.validation.client.SignerCertificateRestClient;
import feign.FeignException;
import java.time.ZonedDateTime;
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
public class SignerCertificatesDownloadServicePseImpl implements SignerCertificateDownloadService {

    private final SignerCertificateRestClient signerCertificateRestClient;
    private final SignerInformationService signerInformationService;

    @Override
    @Scheduled(fixedDelayString = "${dgc.certificatesDownloader.timeInterval}")
    @SchedulerLock(name = "SignerCertificateDownloadService_downloadCertificates", lockAtLeastFor = "PT0S",
        lockAtMostFor = "${dgc.certificatesDownloader.lockLimit}")
    public void downloadCertificates() {

        ResponseEntity<List<String>> responseEntity;

        try {
            responseEntity = signerCertificateRestClient.getKidList();
        } catch (FeignException e) {
            log.error("Download of kid list failed with exception. Service responded with status code: {}",
                e.status());
            return;
        }

        List<String> kidList = responseEntity.getBody();
        if (responseEntity.getStatusCode() != HttpStatus.OK || kidList == null) {
            log.error("Download of kid list failed. Service responded with status code: {}",
                responseEntity.getStatusCode());
            return;
        }

        log.info("Got Response from Service, List contains kids: {}", kidList.size());

        List<TrustListItem> items = getTrustListItems(kidList);

        if (!items.isEmpty()) {
            signerInformationService.updateTrustedCertsList(items);
        } else {
            log.warn("The download of the certificates seems to fail, as the download connector "
                + "returns an empty list. No data will be changed.");
        }

        log.info("Download finished, Downloaded certificates: {}", items.size());

    }

    private List<TrustListItem> getTrustListItems(List<String> kidList) {

        List<TrustListItem> items = new ArrayList<>();
        ResponseEntity<String> responseEntity;
        String resumeToken = "";

        do {
            try {
                responseEntity = signerCertificateRestClient.getCertificate(resumeToken);
            } catch (FeignException e) {
                log.error("Download of certificate failed with exception. Service responded with status code: {}",
                    e.status());
                return new ArrayList<>();
            }

            if (responseEntity.getStatusCode() != HttpStatus.OK 
                &&
                responseEntity.getStatusCode() != HttpStatus.NO_CONTENT) {
                log.error("Download of certificate failed. Service responded with status code: {}",
                    responseEntity.getStatusCode());
                return new ArrayList<>();
            }

            resumeToken = responseEntity.getHeaders().getFirst("X-RESUME-TOKEN");
            String kid = responseEntity.getHeaders().getFirst("X-KID");
            String certificateData = responseEntity.getBody();

            if (kidList.contains(kid) && certificateData != null) {
                TrustListItem trustListItem = new TrustListItem();
                trustListItem.setKid(kid);
                trustListItem.setTimestamp(ZonedDateTime.now());
                trustListItem.setRawData(certificateData);
                items.add(trustListItem);
            }
        } while (responseEntity.getStatusCode() == HttpStatus.OK);

        return items;
    }

}
