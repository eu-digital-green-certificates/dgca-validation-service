/*-
 * ---license-start
 * eu-digital-green-certificates / dgca-verifier-service
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


import com.nimbusds.jose.util.X509CertUtils;
import eu.europa.ec.dgc.gateway.connector.model.TrustListItem;
import eu.europa.ec.dgc.validation.entity.SignerInformationEntity;
import eu.europa.ec.dgc.validation.repository.SignerInformationRepository;
import eu.europa.ec.dgc.validation.restapi.dto.KidDto;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jcajce.provider.asymmetric.X509;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Component
@RequiredArgsConstructor
public class SignerInformationService {

    private final SignerInformationRepository signerInformationRepository;


    /**
     * Method to query the db for a certificate with a resume token.
     *
     * @param resumeToken defines which certificate should be returned.
     * @return Optional holding the certificate if found.
     */
    public Optional<SignerInformationEntity> getCertificate(Long resumeToken) {
        if (resumeToken == null) {
            return signerInformationRepository.findFirstByIdIsNotNullOrderByIdAsc();
        } else {
            return signerInformationRepository.findFirstByIdGreaterThanOrderByIdAsc(resumeToken);
        }
    }

    public List<Certificate> getCertificates(String kid) {
        List<Certificate> certificates = new ArrayList<>();
        for (SignerInformationEntity signerInformationEntity : signerInformationRepository.findAllByKid(kid)) {
            Certificate certificate = X509CertUtils.parse(signerInformationEntity.getRawData());
            if (certificate!=null) {
                certificates.add(certificate);
            }
        }
        return certificates;
    }


    /**
     * Method to query the db for a list of kid from all certificates.
     *
     * @return A list of kids of all certificates found. If no certificate was found an empty list is returned.
     */
    public List<String> getListOfValidKids() {
        ArrayList<String> responseArray = new ArrayList<>();

        List<KidDto> validIds = signerInformationRepository.findAllByOrderByIdAsc();

        for (KidDto validId : validIds) {
            responseArray.add(validId.getKid());
        }

        return responseArray;
    }


    /**
     * Method to synchronise the certificates in the db with the given List of trusted certificates.
     *
     * @param trustedCerts defines the list of trusted certificates.
     *
     */
    @Transactional
    public void updateTrustedCertsList(List<TrustListItem> trustedCerts) {

        List<String> trustedCertsKids = trustedCerts.stream().map(TrustListItem::getKid).collect(Collectors.toList());
        List<String> alreadyStoredCerts = getListOfValidKids();

        if (trustedCertsKids.isEmpty()) {
            signerInformationRepository.deleteAll();
        } else {
            signerInformationRepository.deleteByKidNotIn(trustedCertsKids);
        }


        for (TrustListItem cert : trustedCerts) {
            if (!alreadyStoredCerts.contains(cert.getKid())) {
                saveSignerCertificate(cert.getKid(),cert.getTimestamp(), cert.getRawData());
            }
        }
    }

    /**
     * Method adds a new SignerInformationEntity to the db.
     *
     * @param kid defines the kid of the new SignerInformationEntity.
     * @param createdAt defines the createdAt timestamp of the new SignerInformationEntity.
     * @param rawData defines the raw certificate data of the new SignerInformationEntity.
     *
     */
    private void saveSignerCertificate(String kid, ZonedDateTime createdAt, String rawData) {
        SignerInformationEntity signerEntity = new SignerInformationEntity();
        signerEntity.setKid(kid);
        signerEntity.setCreatedAt(createdAt);
        signerEntity.setRawData(rawData);

        signerInformationRepository.save(signerEntity);
    }

}