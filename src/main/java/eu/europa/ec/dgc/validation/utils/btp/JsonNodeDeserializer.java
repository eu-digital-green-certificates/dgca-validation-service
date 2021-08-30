package eu.europa.ec.dgc.validation.utils.btp;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import java.lang.reflect.Type;

public class JsonNodeDeserializer implements JsonDeserializer<JsonNode> {
    @Override
    public JsonNode deserialize(JsonElement jsonElement, Type type,
                                JsonDeserializationContext jsonDeserializationContext) throws JsonParseException {
        try {
            return new ObjectMapper().readTree(jsonElement.getAsJsonObject().toString());
        } catch (JsonProcessingException e) {
            throw new JsonParseException(e);
        }
    }
}
