package eu.europa.ec.dgc.validation.service;


import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.TypeAdapter;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import com.sap.cloud.sdk.cloudplatform.connectivity.DestinationAccessor;
import com.sap.cloud.sdk.cloudplatform.connectivity.HttpClientAccessor;
import com.sap.cloud.sdk.cloudplatform.connectivity.HttpDestination;
import eu.europa.ec.dgc.validation.model.ValueSetItem;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
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
public class ValueSetsDownloadServiceBtpImpl implements ValueSetsDownloadService {

    private static final String DGCG_DESTINATION = "dgcg-destination";
    private static final String DCCG_VALUE_SETS_ENDPOINT = "/valuesets";

    private final ValueSetService valueSetService;


    @Override
    @Scheduled(fixedDelayString = "${dgc.valueSetsDownload.timeInterval}")
    @SchedulerLock(name = "GatewayDataDownloadService_downloadValueSets", lockAtLeastFor = "PT0S",
            lockAtMostFor = "${dgc.valueSetsDownload.lockLimit}")
    public void downloadValueSets() {
        try {
            initializeLogging();
            log.debug("Value sets download started.");
            List<ValueSetItem> valueSetItems;
            List<String> valueSetIds = fetchValueSetIds();

            try {
                valueSetItems = valueSetService.createValueSetItemListFromMap(fetchValueSets(valueSetIds));
                log.debug("Downloaded {} value set items.", valueSetItems.size());
            } catch (NoSuchAlgorithmException e) {
                log.error("Failed to hash value set on download.",e);
                return;
            }

            if (!valueSetItems.isEmpty()) {
                valueSetService.updateValueSets(valueSetItems);
            } else {
                log.warn("The download of the value sets seems to fail, as the download connector "
                        + "returns an empty list. No data will be changed.");
            }

            log.debug("Value sets download finished.");
        } finally {
            cleanLogging();
        }
    }

    private List<String> fetchValueSetIds() {
        HttpDestination httpDestination = DestinationAccessor.getDestination(DGCG_DESTINATION).asHttp();
        HttpClient httpClient = HttpClientAccessor.getHttpClient(httpDestination);
        List<String> valueSetIds = new ArrayList<>();

        try {
            HttpResponse response = httpClient.execute(RequestBuilder.get(DCCG_VALUE_SETS_ENDPOINT).build());
            valueSetIds = new ArrayList<>(gson().fromJson(toJsonString(response.getEntity()),
                    new TypeToken<List<String>>() {}.getType()));
        } catch (IOException e) {
            log.error("Could not fetch value set IDs from gateway: {}", e.getMessage());
        }

        return valueSetIds;
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

    private String toJsonString(HttpEntity entity) throws IOException {
        return EntityUtils.toString(entity);
    }

    private Map<String, String> fetchValueSets(List<String> valueSetIds) {
        HttpDestination httpDestination = DestinationAccessor.getDestination(DGCG_DESTINATION).asHttp();
        HttpClient httpClient = HttpClientAccessor.getHttpClient(httpDestination);
        Map<String, String> valueSets = new HashMap<>();

        for (String valueSetId : valueSetIds) {
            try {
                HttpResponse response = httpClient
                        .execute(RequestBuilder.get(DCCG_VALUE_SETS_ENDPOINT + "/" + valueSetId).build());
                valueSets.put(valueSetId, toJsonString(response.getEntity()));
            } catch (IOException e) {
                log.warn("Could not fetch value set with ID '{}': {}", valueSetId, e.getMessage(), e);
            }
        }

        return valueSets;
    }

    private static final String CORRELATION_ID_LOG_VAR_NAME = "correlation_id";

    private void initializeLogging() {
        MDC.put(CORRELATION_ID_LOG_VAR_NAME, UUID.randomUUID().toString());
    }

    private void cleanLogging() {
        MDC.remove(CORRELATION_ID_LOG_VAR_NAME);
    }

}
