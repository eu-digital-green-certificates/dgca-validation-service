package eu.europa.ec.dgc.validation.service.Mocks;

import java.util.List;

import dgca.verifier.app.engine.data.Rule;
import eu.europa.ec.dgc.validation.service.RulesCache;

public class BusinessRulesCacheMock implements RulesCache {

   private List<Rule> rules; 
   public BusinessRulesCacheMock(List<Rule> rules)
   {
      this.rules = rules;
   }

    @Override
    public List<Rule> provideRules(String countryOfArrival, String issuerCountry) {
        // TODO Auto-generated method stub
        return rules;
    }

    
}
