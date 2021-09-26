package eu.europa.ec.dgc.validation.service;

import java.util.List;
import java.util.Map;

public interface ValueSetCache {
    public Map<String, List<String>> provideValueSets();

    public Map<String, List<String>> getValueSets();
}
