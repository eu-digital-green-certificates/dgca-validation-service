package eu.europa.ec.dgc.validation.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import dgca.verifier.app.decoder.JsonSchemaKt;
import dgca.verifier.app.engine.AffectedFieldsDataRetriever;
import dgca.verifier.app.engine.CertLogicEngine;
import dgca.verifier.app.engine.DefaultAffectedFieldsDataRetriever;
import dgca.verifier.app.engine.DefaultCertLogicEngine;
import dgca.verifier.app.engine.DefaultJsonLogicValidator;
import dgca.verifier.app.engine.JsonLogicValidator;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class DccVerificationConfig {
    @Bean
    ObjectMapper objectMapper() {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        return objectMapper;
    }

    @Bean
    AffectedFieldsDataRetriever affectedFieldsDataRetriever(ObjectMapper objectMapper) throws JsonProcessingException {
        JsonNode jsonNode = objectMapper.readTree(JsonSchemaKt.JSON_SCHEMA_V1);
        return new DefaultAffectedFieldsDataRetriever(jsonNode, objectMapper);
    }

    @Bean
    JsonLogicValidator jsonLogicValidator() {
        return new DefaultJsonLogicValidator();
    }

    @Bean
    CertLogicEngine certLogicEngine(AffectedFieldsDataRetriever affectedFieldsDataRetriever,
                                    JsonLogicValidator jsonLogicValidator) {
        return new DefaultCertLogicEngine(affectedFieldsDataRetriever, jsonLogicValidator);
    }
}
