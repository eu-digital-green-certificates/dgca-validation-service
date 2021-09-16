/*-
 * ---license-start
 * eu-digital-green-certificates / dgca-validation-service
 * ---
 * Copyright (C) 2021 T-Systems International GmbH and all other contributors
 * ---
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ---license-end
 */


package eu.europa.ec.dgc.validation.client;

import feign.Client;
import feign.Logger;
import feign.httpclient.ApacheHttpClient;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import lombok.RequiredArgsConstructor;
import org.apache.http.impl.client.HttpClientBuilder;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Profile("pse")
@Configuration
@RequiredArgsConstructor
@EnableFeignClients
public class RestClientConfig {


    /**
     * Feign Client for connection to business rules service.
     *
     * @return Instance of HttpClient
     */
    @Bean
    public Client client() throws
        UnrecoverableKeyException, CertificateException,
        IOException, NoSuchAlgorithmException,
        KeyStoreException, KeyManagementException {

        return new ApacheHttpClient(HttpClientBuilder.create()
            .build());
    }

    @Bean
    Logger.Level feignLoggerLevel() {
        return Logger.Level.BASIC;
    }

}
