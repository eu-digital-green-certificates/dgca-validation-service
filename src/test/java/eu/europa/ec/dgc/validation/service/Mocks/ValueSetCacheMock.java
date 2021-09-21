package eu.europa.ec.dgc.validation.service.Mocks;

import java.util.List;
import java.util.Map;

import eu.europa.ec.dgc.validation.service.ValueSetCache;

public class ValueSetCacheMock implements ValueSetCache {

    private Map<String, List<String>> valueSets;

    public ValueSetCacheMock(Map<String, List<String>> valueSets) {
        this.valueSets = valueSets;
    }

    @Override
    public Map<String, List<String>> provideValueSets() {
        return valueSets;
    }

    @Override
    public Map<String, List<String>> getValueSets() {
        return valueSets;
    }
}
