package eu.europa.ec.dgc.validation.service;

import dgca.verifier.app.engine.data.Rule;
import java.util.List;

public interface RulesCache {
    public List<Rule> provideRules(String countryOfArrival, String issuerCountry);
}
