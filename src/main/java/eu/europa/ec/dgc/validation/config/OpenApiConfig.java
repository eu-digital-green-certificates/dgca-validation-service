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

package eu.europa.ec.dgc.validation.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import java.util.Optional;
import lombok.Generated;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.info.BuildProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Generated
@Configuration
@RequiredArgsConstructor
public class OpenApiConfig {

    private final Optional<BuildProperties> buildProperties;

    /**
     * Configure the OpenApi bean with title and version.
     *
     * @return the OpenApi bean.
     */
    @Bean
    public OpenAPI openApi() {
        String version;
        if (buildProperties.isPresent()) {
            version = buildProperties.get().getVersion();
        } else {
            // build properties is not available if starting from IDE without running mvn before (so fake this)
            version = "dev";
        }
        return new OpenAPI()
            .info(new Info()
                .title("EU Digital COVID Certificate Validation Service")
                .description("The API provides functionalities for validating  "
                    + "EU digital COVID certificates.")
                .version(version)
                .license(new License()
                    .name("Apache 2.0")
                    .url("https://www.apache.org/licenses/LICENSE-2.0")));
    }
}
