package de.serdioa.rest.ping.client;

import de.serdioa.boot.autoconfigure.webclient.ClientHttpConnectorConfiguration;
import org.springframework.boot.web.reactive.function.client.WebClientCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.client.AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.InMemoryReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction;


//@Configuration
//@LoadBalancerClient(name = "ping-service", configuration = PingApiServerConfiguration.class)
@Configuration
@Import({ClientHttpConnectorConfiguration.class})
public class WebClientConfiguration {

    @Bean
    public WebClientCustomizer webClientOauthCustomizer(ReactiveClientRegistrationRepository clientRegistrationRepository) {

        InMemoryReactiveOAuth2AuthorizedClientService clientService =
                new InMemoryReactiveOAuth2AuthorizedClientService(clientRegistrationRepository);

        AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager clientManager =
                new AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager(clientRegistrationRepository, clientService);

        ServerOAuth2AuthorizedClientExchangeFilterFunction oauth =
                new ServerOAuth2AuthorizedClientExchangeFilterFunction(clientManager);
        oauth.setDefaultClientRegistrationId("ping");

        return (webClientBuilder) -> webClientBuilder.filter(oauth);
    }
}
