package de.serdioa.rest.ping.client;

import de.serdioa.rest.generated.ping.client.ApiClient;
import de.serdioa.rest.generated.ping.client.api.PingApi;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;


@Configuration
public class PingApiConfiguration {

    @Bean
    @ConfigurationProperties("api.client.ping")
    public ApiClientProperties pingApiClientProperties() {
        return new ApiClientProperties();
    }


    @Bean
    public ApiClient pingApiClient(WebClient.Builder webClientBuilder, ApiClientProperties pingApiClientProperties) {
        WebClient webClient = webClientBuilder.build();

        ApiClient apiClient = new ApiClient(webClient);
        apiClient.setBasePath(pingApiClientProperties.getBasePath());

        return apiClient;
    }


    @Bean
    public PingApi pingApi(ApiClient apiClient) {
        return new PingApi(apiClient);
    }
}
