package eu.europa.ec.dgc.validation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import dgca.verifier.app.engine.AffectedFieldsDataRetriever;
import dgca.verifier.app.engine.CertLogicEngine;
import dgca.verifier.app.engine.DefaultCertLogicEngine;
import dgca.verifier.app.engine.DefaultJsonLogicValidator;
import dgca.verifier.app.engine.JsonLogicValidator;
import dgca.verifier.app.engine.ValidationResult;
import dgca.verifier.app.engine.data.CertificateType;
import dgca.verifier.app.engine.data.ExternalParameter;
import dgca.verifier.app.engine.data.Rule;
import dgca.verifier.app.engine.data.source.remote.rules.RuleRemote;
import dgca.verifier.app.engine.data.source.remote.rules.RuleRemoteMapperKt;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;

import static eu.ehn.dcc.certlogic.CertlogicKt.evaluate;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

class CertlogicTest
{
    private String STANDARD_VERSION = "1.0.0";
    private ObjectMapper objectMapper = new ObjectMapper();

    @Test
    public void testCertlogic() throws Exception {
        System.out.println("hallo");

        String ruleJson = "{\n" +
                "    \"if\": [{\n" +
                "            \"var\": \"a\"\n" +
                "        }, {\n" +
                "            \">\": [3,{\"var\": \"a\"}]\n" +
                "        },\n" +
                "        false\n" +
                "    ]\n" +
                "}";
        String dataJson = "{\"a\": 5}";

        JsonNode data = objectMapper.readTree(dataJson);
        JsonNode rule = objectMapper.readTree(ruleJson);
        JsonNode res = evaluate(rule, data);
        System.out.println(objectMapper.writeValueAsString(res));
    }

    @Test
    public void certLogicEngine() throws Exception {
        objectMapper.registerModule(new JavaTimeModule());

        String payload = Files.readString(Path.of("src/test/resources/hcert.json"));
        RuleRemote ruleRemote = objectMapper.readValue(new File("src/test/resources/rule.json"), RuleRemote.class);

        JsonLogicValidator jsonLogicValidator = new DefaultJsonLogicValidator();
        AffectedFieldsDataRetriever affectedFieldsDataRetriever = mock(AffectedFieldsDataRetriever.class);
        //doReturn(true).when(jsonLogicValidator).isDataValid(any(), any());
        doReturn("").when(affectedFieldsDataRetriever).getAffectedFieldsData(any(), any(), any());

        CertLogicEngine certLogicEngine = new DefaultCertLogicEngine(affectedFieldsDataRetriever, jsonLogicValidator);

        List<Rule> rules = new ArrayList<>();
        rules.add(RuleRemoteMapperKt.toRule(ruleRemote));

        ExternalParameter externalParameter = new ExternalParameter(
                ZonedDateTime.now(),
                Collections.emptyMap(),
                "de",
                ZonedDateTime.now(),
                ZonedDateTime.now(),
                "de",
                "kid",
                ""
        );

        List<ValidationResult> validationResult = certLogicEngine.validate(CertificateType.VACCINATION, STANDARD_VERSION, rules, externalParameter, payload);
        System.out.println(objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(validationResult));

    }
}
