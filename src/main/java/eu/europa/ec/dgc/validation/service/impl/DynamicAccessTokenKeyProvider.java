package eu.europa.ec.dgc.validation.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.ec.dgc.validation.config.DgcConfigProperties;
import eu.europa.ec.dgc.validation.exception.DccException;
import eu.europa.ec.dgc.validation.service.AccessTokenKeyProvider;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
@ConditionalOnProperty(prefix="dgc", name="decoratorUrl")
public class DynamicAccessTokenKeyProvider implements AccessTokenKeyProvider {
    private final Map<String,PublicKey> publicKeys = new HashMap<>();
    private final DgcConfigProperties dgcConfigProperties;

    @PostConstruct
    public void loadKeys() throws IOException, InterruptedException {
        String decoratorUrl = dgcConfigProperties.getDecoratorUrl();
        log.info("accessing identity document from decorator url: {}",decoratorUrl);
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(decoratorUrl))
            .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode()!=200) {
            loadKeysFrom(response.body());
        } else {
            throw new DccException("can not load identity document from "+decoratorUrl
                +" response code "+response.statusCode());
        }
    }

    public void loadKeysFrom(String identityJson) throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode json = objectMapper.readTree(identityJson);
        JsonNode verificationMethods = json.get("verificationMethod");
        if (verificationMethods!=null && verificationMethods.isArray()) {
            for (JsonNode verificationMethod : verificationMethods) {
                JsonNode idNode = verificationMethod.get("id");
                if (idNode!=null && idNode.isTextual()) {
                    String id = idNode.asText();
                    if (id.contains("AccessTokenSignKey")) {
                        JsonNode publicKeyJWK = verificationMethod.get("publicKeyJWK");
                        if (publicKeyJWK!=null && publicKeyJWK.isObject()) {
                            JsonNode kidNode = publicKeyJWK.get("kid");
                            JsonNode x5cNode = publicKeyJWK.get("x5c");
                            if (kidNode!=null && kidNode.isTextual()
                                && x5cNode!=null && x5cNode.isTextual()) {
                                String kid = kidNode.asText();
                                String x5c = x5cNode.asText();
                                importKey(kid, x5c);
                            }
                        }
                    }
                }
            }
        }
    }

    private void importKey(String kid, String x5c)  {
        try {
            CertificateFactory certificateFactory = CertificateFactory
                .getInstance("X.509");
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(Base64.decode(x5c));
            Certificate certificate = certificateFactory
                .generateCertificate(byteArrayInputStream);
            publicKeys.put(kid, certificate.getPublicKey());
            log.info("access key for kid={} imported from identity json",kid);
        } catch (CertificateException e) {
            log.warn("can not import access public key from identity json for kid: "+kid,e);
        }

    }

    @Override
    public PublicKey getPublicKey(String kid) {
        PublicKey publicKey = publicKeys.get(kid);
        if (publicKey == null) {
            throw new DccException("can not find access key with kid: " + kid);
        }
        return publicKey;
    }
}
