package eu.europa.ec.dgc.validation.service;


import com.fasterxml.jackson.databind.JsonNode;
import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;
import com.google.gson.TypeAdapter;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import com.sap.cloud.sdk.cloudplatform.connectivity.DestinationAccessor;
import com.sap.cloud.sdk.cloudplatform.connectivity.HttpClientAccessor;
import com.sap.cloud.sdk.cloudplatform.connectivity.HttpDestination;
import eu.europa.ec.dgc.gateway.connector.dto.ValidationRuleDto;
import eu.europa.ec.dgc.gateway.connector.model.ValidationRule;
import eu.europa.ec.dgc.signing.SignedStringMessageParser;
import eu.europa.ec.dgc.validation.model.BusinessRuleItem;
import eu.europa.ec.dgc.validation.utils.btp.JsonNodeDeserializer;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.util.EntityUtils;
import org.slf4j.MDC;
import org.springframework.context.annotation.Profile;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Slf4j
@RequiredArgsConstructor
@Component
@Profile("btp")
public class BusinessRulesDownloadServiceBtpImpl implements BusinessRulesDownloadService {

    private static final String DGCG_DESTINATION = "dgcg-destination";
    private static final String DCCG_BUSINESS_RULES_ENDPOINT = "/rules";
    private static final String DCCG_COUNTRY_LIST_ENDPOINT = "/countrylist";

    private final BusinessRuleService businessRuleService;

    @Override
    @Scheduled(fixedDelayString = "${dgc.businessRulesDownload.timeInterval}")
    @SchedulerLock(name = "GatewayDataDownloadService_downloadBusinessRules", lockAtLeastFor = "PT0S",
            lockAtMostFor = "${dgc.businessRulesDownload.lockLimit}")
    public void downloadBusinessRules() {
        try {
            initializeLogging();
            log.debug("Business rules download started.");

            //List<X509CertificateHolder> uploadCerts = fetchUploadCerts(httpClient);
            List<String> countryCodes = fetchCountryList();

            List<BusinessRuleItem> ruleItems = new ArrayList<>();
            try {
                ruleItems = businessRuleService.createBusinessRuleItemList(fetchValidationRulesAndVerify(countryCodes));
            } catch (NoSuchAlgorithmException e) {
                log.error("Could not create business rule item list: {}", e.getMessage(), e);
            }

            if (!ruleItems.isEmpty()) {
                businessRuleService.updateBusinessRules(ruleItems);
            } else {
                log.warn("The download of the business rules seems to fail, as the download connector "
                        + "returns an empty list. No data will be changed.");
            }

            log.info("Business rules download finished.");
        } finally {
            cleanLogging();
        }

    }

    private List<String> fetchCountryList() {
        HttpDestination httpDestination = DestinationAccessor.getDestination(DGCG_DESTINATION).asHttp();
        HttpClient httpClient = HttpClientAccessor.getHttpClient(httpDestination);
        List<String> countryList = new ArrayList<>();

        try {
            HttpResponse response = httpClient.execute(RequestBuilder.get(DCCG_COUNTRY_LIST_ENDPOINT).build());
            countryList = new ArrayList<>(gson().fromJson(toJsonString(response.getEntity()),
                    new TypeToken<List<String>>() {}.getType()));
        } catch (IOException e) {
            log.error("Could not fetch country list from gateway: {}", e.getMessage(), e);
        }

        return countryList;
    }

    private Gson gson() {
        return new GsonBuilder().registerTypeAdapter(ZonedDateTime.class, new TypeAdapter<ZonedDateTime>() {
            @Override
            public void write(JsonWriter out, ZonedDateTime value) throws IOException {
                out.value(value.toString());
            }

            @Override
            public ZonedDateTime read(JsonReader in) throws IOException {
                return ZonedDateTime.parse(in.nextString());
            }
        })
                .enableComplexMapKeySerialization()
                .create();
    }

    private Gson gsonForValidationRule() {
        return new GsonBuilder().registerTypeAdapter(ZonedDateTime.class, new TypeAdapter<ZonedDateTime>() {
            @Override
            public void write(JsonWriter out, ZonedDateTime value) throws IOException {
                out.value(value.toString());
            }

            @Override
            public ZonedDateTime read(JsonReader in) throws IOException {
                return ZonedDateTime.parse(in.nextString());
            }
        })
                .registerTypeAdapter(JsonNode.class, new JsonNodeDeserializer())
                .setFieldNamingStrategy(FieldNamingPolicy.UPPER_CAMEL_CASE)
                .enableComplexMapKeySerialization()
                .create();
    }

    private String toJsonString(HttpEntity entity) throws IOException {
        return EntityUtils.toString(entity);
    }


    private List<ValidationRule> fetchValidationRulesAndVerify(List<String> countryCodes) {
        HttpDestination httpDestination = DestinationAccessor.getDestination(DGCG_DESTINATION).asHttp();
        HttpClient httpClient = HttpClientAccessor.getHttpClient(httpDestination);
        List<ValidationRule> allRules = new ArrayList<>();

        for (String countryCode : countryCodes) {
            log.debug("Fetching rules for country '{}'...", countryCode);
            try {
                HttpResponse response = httpClient
                        .execute(RequestBuilder.get(DCCG_BUSINESS_RULES_ENDPOINT + "/" + countryCode).build());
                Map<String, ValidationRuleDto[]> fetchedForCountry = gson().fromJson(toJsonString(response.getEntity()),
                        new TypeToken<Map<String, ValidationRuleDto[]>>() {}.getType());

                log.debug("Fetched {} rule(s) for country '{}'. Parsing now...", fetchedForCountry.values().size(),
                        countryCode);
                allRules.addAll(fetchedForCountry.values().stream().flatMap(Arrays::stream).map(this::mapRule)
                        .filter(Objects::nonNull).collect(Collectors.toList()));
            } catch (IOException | JsonSyntaxException e) {
                log.warn("Could not fetch rules for country '{}': {}", countryCode, e.getMessage(), e);
            }
        }

        return allRules;
    }

    private ValidationRule mapRule(ValidationRuleDto dto) {
        try {
            SignedStringMessageParser parser = new SignedStringMessageParser(dto.getCms());
            ValidationRule validationRule = gsonForValidationRule().fromJson(parser.getPayload(), ValidationRule.class);
            validationRule.setRawJson(parser.getPayload());
            return validationRule;
        } catch (JsonSyntaxException e) {
            log.warn("Could not parse validation rule: {}", e.getMessage(), e);
        }
        return null;
    }

    private static final String CORRELATION_ID_LOG_VAR_NAME = "correlation_id";

    private void initializeLogging() {
        MDC.put(CORRELATION_ID_LOG_VAR_NAME, UUID.randomUUID().toString());
    }

    private void cleanLogging() {
        MDC.remove(CORRELATION_ID_LOG_VAR_NAME);
    }

}
