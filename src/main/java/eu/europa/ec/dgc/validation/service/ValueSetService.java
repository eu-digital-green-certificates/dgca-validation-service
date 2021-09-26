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

import eu.europa.ec.dgc.utils.CertificateUtils;
import eu.europa.ec.dgc.validation.entity.ValueSetEntity;
import eu.europa.ec.dgc.validation.model.ValueSetItem;
import eu.europa.ec.dgc.validation.repository.ValueSetRepository;
import eu.europa.ec.dgc.validation.restapi.dto.ValueSetListItemDto;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@RequiredArgsConstructor
@Service
public class ValueSetService {

    private final CertificateUtils certificateUtils;

    private final ValueSetRepository valueSetRepository;


    /**
     * Gets list of all value set ids and hashes.
     */
    public List<ValueSetListItemDto> getValueSetsList() {

        List<ValueSetListItemDto> valueSetItems = valueSetRepository.findAllByOrderByIdAsc();
        return valueSetItems;
    }


    /**
     * Gets a value set by its hash value.
     */
    @Transactional
    public ValueSetEntity getValueSetByHash(String hash) {

        return valueSetRepository.findOneByHash(hash);
    }

    /**
     * Updates the list of value sets.
     *
     * @param valueSets list of actual value sets
     */
    @Transactional
    public void updateValueSets(List<ValueSetItem> valueSets) {
        List<String> valueSetsHashes = valueSets.stream().map(ValueSetItem::getHash).collect(Collectors.toList());
        List<String> alreadyStoredValueSets = getValueSetsHashList();
        log.debug("Got {} value sets from gateway and {} already stored in the database. Processing update now...",
            valueSetsHashes.size(), alreadyStoredValueSets.size());

        if (valueSetsHashes.isEmpty()) {
            log.info("Got no value sets from gateway. Deleting all stored value sets.");
            valueSetRepository.deleteAll();
        } else {
            log.info("Deleting value sets not contained in latest response from gateway.");
            valueSetRepository.deleteByHashNotIn(valueSetsHashes);
        }

        for (ValueSetItem valueSet : valueSets) {
            log.debug("Processing value set with hash '{}'.", valueSet.getHash());
            if (!alreadyStoredValueSets.contains(valueSet.getHash())) {
                saveValueSet(valueSet.getHash(), valueSet.getId(), valueSet.getRawData());
                log.debug("Saved value set '{}'.", valueSet.getHash());
            } else {
                log.debug("Value set already exists in database. Persisting skipped.");
            }
        }

    }

    /**
     * Saves a value set.
     *
     * @param hash         The hash value of the value set data.
     * @param valueSetName The name of the value set.
     * @param valueSetData The raw value set data.
     */
    @Transactional
    public void saveValueSet(String hash, String valueSetName, String valueSetData) {

        ValueSetEntity vse = new ValueSetEntity();
        vse.setHash(hash);
        vse.setId(valueSetName);
        vse.setRawData(valueSetData);

        valueSetRepository.save(vse);
    }

    /**
     * Creates a List of value set items from a map of value sets without hashes.
     *
     * @param valueSetMap the map containing the row value sets.
     * @return List of ValueSetItems
     */
    public List<ValueSetItem> createValueSetItemListFromMap(Map<String, String> valueSetMap)
        throws NoSuchAlgorithmException {
        List<ValueSetItem> valueSetItems = new ArrayList<>();

        for (Map.Entry<String, String> vse : valueSetMap.entrySet()) {
            ValueSetItem valueSetItem = new ValueSetItem();
            valueSetItem.setHash(certificateUtils.calculateHash(vse.getValue().getBytes(StandardCharsets.UTF_8)));
            valueSetItem.setId(vse.getKey());
            valueSetItem.setRawData(vse.getValue());
            valueSetItems.add(valueSetItem);
        }

        return valueSetItems;
    }

    /**
     * Gets a list of hash values of all stored value sets.
     *
     * @return List of hash values
     */
    private List<String> getValueSetsHashList() {
        return getValueSetsList().stream().map(ValueSetListItemDto::getHash).collect(Collectors.toList());
    }

}
