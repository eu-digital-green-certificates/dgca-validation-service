package eu.europa.ec.dgc.validation.service;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import javax.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@RequiredArgsConstructor
@Component
public class ResultCallbackService {
    private final HttpClient client = HttpClient.newHttpClient();
    private final ExecutorService executor = Executors.newFixedThreadPool(5);

    /**
     * schedule callback.
     * @param callbackUrl url
     * @param resultToken jwt token
     */
    public void scheduleCallback(String callbackUrl, String resultToken) {
        log.debug("schedule callback");
        try {
            URL url = new URL(callbackUrl);
            if (url.getProtocol().equals("http") || url.getProtocol().equals("https")) {
                executor.submit(() -> {
                    makeCallback(callbackUrl, resultToken);
                });
            } else {
                log.warn("unsupported callback protocol: " + callbackUrl);
            }
        } catch (MalformedURLException e) {
            log.warn("malformed callback url: {}", callbackUrl);
        }
    }

    /**
     * terminate.
     */
    @PreDestroy
    public void terminateExecutor() {
        try {
            executor.awaitTermination(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            log.warn("can not shut down callback executor", e);
        }
    }

    private void makeCallback(String callbackUrl, String resultToken) {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(callbackUrl))
                .header("Content-Type", "application/jwt")
                .header("X-Version","1.0")
                .PUT(HttpRequest.BodyPublishers.ofString(resultToken))
                .build();
        try {
            HttpResponse<String> response = null;
            response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                log.info("callback not successful to: {} status: ", callbackUrl, response.statusCode());
            }
        } catch (IOException | InterruptedException e) {
            log.warn("can not call callback to: {} ", callbackUrl);
        }
    }

}
