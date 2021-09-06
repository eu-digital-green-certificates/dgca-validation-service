package eu.europa.ec.dgc.validation.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import dgca.verifier.app.engine.CertLogicEngine;
import dgca.verifier.app.engine.data.Rule;
import dgca.verifier.app.engine.data.source.remote.rules.RuleRemote;
import dgca.verifier.app.engine.data.source.remote.rules.RuleRemoteMapperKt;
import eu.europa.ec.dgc.utils.CertificateUtils;
import eu.europa.ec.dgc.validation.entity.BusinessRuleEntity;
import eu.europa.ec.dgc.validation.exception.DccException;
import eu.europa.ec.dgc.validation.restapi.dto.BusinessRuleListItemDto;
import lombok.RequiredArgsConstructor;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalAmount;
import java.time.temporal.TemporalUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class RulesCache {
    private final BusinessRuleService businessRuleService;
    private final ObjectMapper objectMapper;
    private Map<String,List<Rule>> rulesMap = new HashMap<>();
    private LocalTime expireTime;

    private final static TemporalAmount expireSpan = Duration.ofMinutes(15);

    public List<Rule> provideRules(String countryOfDeparture) {
        List<Rule> rules = rulesMap.get(countryOfDeparture);
        if (rules==null || expireTime==null || expireTime.isAfter(LocalTime.now())) {
            rules = getRules(countryOfDeparture);
            rulesMap.put(countryOfDeparture, rules);
            expireTime = LocalTime.now().plus(expireSpan);
        }
        return rules;
    }

    @NotNull
    private List<Rule> getRules(String countryOfDeparture) {
        List<BusinessRuleListItemDto> rulesDto = businessRuleService.getBusinessRulesListForCountry(countryOfDeparture);
        List<Rule> rules = new ArrayList<>();
        for (BusinessRuleListItemDto ruleDto : rulesDto) {
            BusinessRuleEntity ruleData = businessRuleService.getBusinessRuleByCountryAndHash(ruleDto.getCountry(), ruleDto.getHash());
            if (ruleData!=null) {
                try {
                    RuleRemote ruleRemote = objectMapper.readValue(ruleData.getRawData(), RuleRemote.class);
                    rules.add(RuleRemoteMapperKt.toRule(ruleRemote));
                } catch (JsonProcessingException e) {
                    throw new DccException("can not parse rule", e);
                }
            }
        }
        return rules;
    }
}
