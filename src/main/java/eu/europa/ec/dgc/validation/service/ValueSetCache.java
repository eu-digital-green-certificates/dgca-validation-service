package eu.europa.ec.dgc.validation.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import dgca.verifier.app.engine.data.Rule;
import dgca.verifier.app.engine.data.source.remote.valuesets.ValueSetRemote;
import eu.europa.ec.dgc.validation.entity.ValueSetEntity;
import eu.europa.ec.dgc.validation.exception.DccException;
import eu.europa.ec.dgc.validation.restapi.dto.ValueSetListItemDto;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalTime;
import java.time.temporal.TemporalAmount;
import java.util.*;

@Service
@RequiredArgsConstructor
public class ValueSetCache {
    private final ObjectMapper objectMapper;
    private final ValueSetService valueSetService;
    private Map<String, List<String>> valueSets;
    private LocalTime expireTime;

    private final static TemporalAmount expireSpan = Duration.ofMinutes(15);

    public Map<String, List<String>> provideValueSets() {
        if (valueSets==null || expireTime==null || expireTime.isAfter(LocalTime.now())) {
            valueSets = getValueSets();
            expireTime = LocalTime.now().plus(expireSpan);
        }
        return valueSets;
    }

    public Map<String, List<String>> getValueSets() {
        Map<String, List<String>> valueSets = new HashMap<>();
        for (ValueSetListItemDto valueSetListItemDto : valueSetService.getValueSetsList()) {
            ValueSetEntity valueSetEntity = valueSetService.getValueSetByHash(valueSetListItemDto.getHash());
            try {
                ValueSetRemote valueSet = objectMapper.readValue(valueSetEntity.getRawData(), ValueSetRemote.class);
                List<String> ids = new ArrayList<>();
                for (Iterator<String> it = valueSet.getValueSetValues().fieldNames(); it.hasNext(); ) {
                    String fieldName = it.next();
                    ids.add(fieldName);
                }
                valueSets.put(valueSetEntity.getId(), ids);
            } catch (JsonProcessingException e) {
                throw new DccException("can not parse value list",e);
            }
        }
        return valueSets;
    }
}
