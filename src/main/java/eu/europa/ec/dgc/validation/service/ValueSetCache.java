package eu.europa.ec.dgc.validation.service;

import java.util.*;

public interface ValueSetCache {
    public Map<String, List<String>> provideValueSets();
    public Map<String, List<String>> getValueSets();
}
