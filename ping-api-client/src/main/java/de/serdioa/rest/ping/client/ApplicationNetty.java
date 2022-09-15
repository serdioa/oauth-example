package de.serdioa.rest.ping.client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.function.Consumer;

import de.serdioa.rest.generated.ping.client.ApiClient;
import de.serdioa.rest.generated.ping.client.api.PingApi;
import de.serdioa.rest.generated.ping.client.model.Ping;
import de.serdioa.rest.generated.ping.client.model.Pong;

import org.springframework.boot.CommandLineRunner;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.security.oauth2.client.AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.InMemoryReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;


// https://andrew-flower.com/blog/webclient-body-logging
// https://andrew-flower.com/blog/webclient-body-logging
// https://dev.to/stevenpg/logging-with-spring-webclient-2j6o
// https://stackoverflow.com/questions/65532492/how-to-access-to-request-body-using-webflux-and-netty-httpclient
// https://andrew-flower.com/blog/Custom-HMAC-Auth-with-Spring-WebClient
public class ApplicationNetty implements CommandLineRunner {

    private ApiClient apiClient;
    private PingApi pingApi;


    public static void main(String[] args) throws Exception {
        new ApplicationNetty().run(args);
    }


    public void run(String... args) throws Exception {
        ClientRegistration clientRegistration = ClientRegistration
                .withRegistrationId("test")
                .tokenUri("http://localhost:8070/oauth2/token")
                .clientId("aladdin")
                .clientSecret("sesame")
                .scope("read", "write")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();

        ReactiveClientRegistrationRepository clientRegistrationRespository =
                new InMemoryReactiveClientRegistrationRepository(clientRegistration);

        InMemoryReactiveOAuth2AuthorizedClientService clientService =
                new InMemoryReactiveOAuth2AuthorizedClientService(clientRegistrationRespository);

        AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager clientManager =
                new AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager(clientRegistrationRespository, clientService);

        ServerOAuth2AuthorizedClientExchangeFilterFunction oauth =
                new ServerOAuth2AuthorizedClientExchangeFilterFunction(clientManager);
        oauth.setDefaultClientRegistrationId("test");

        HttpClient httpClient = HttpClient.create().doOnRequest((request, conn) -> {
            System.out.println("!!! httpClient: doOnRequest");
        }).doOnResponse((response, conn) -> {
            System.out.println("!!! httpClient: doOnResponse");
        });

        Consumer<byte[]> encoderPayloadConsumer = (payload) -> {
            System.out.println("Encoder payload: " + new String(payload, StandardCharsets.UTF_8));
        };

        Consumer<byte[]> decoderPayloadConsumer = (payload) -> {
            System.out.println("Decoder payload: " + new String(payload, StandardCharsets.UTF_8));
        };
        LoggingJsonEncoder loggingEncoder = new LoggingJsonEncoder(encoderPayloadConsumer);
        LoggingJsonDecoder loggingDecoder = new LoggingJsonDecoder(decoderPayloadConsumer);

        WebClient webClient = WebClient.builder()
                .codecs(codecConfigurer -> {
                    codecConfigurer.defaultCodecs().jackson2JsonEncoder(loggingEncoder);
                    codecConfigurer.defaultCodecs().jackson2JsonDecoder(loggingDecoder);
                })
                .filter(oauth)
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .build();

        this.apiClient = new ApiClient(webClient);
        this.apiClient.setBasePath("http://localhost:8080");

        this.pingApi = new PingApi(this.apiClient);

        while (this.parseAndProcessCommand()) {
            // Main command-processing loop.
        }
    }


    private boolean parseAndProcessCommand() throws IOException {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String str = in.readLine();
        String[] items = str.split("\\s+");
        String token = (items.length > 1 ? items[1] : null);

        System.out.printf("Items (%d): %s%n", items.length, Arrays.toString(items));

        if (items.length > 0) {
            switch (items[0]) {
                case "exit":
                    return false;
                case "get":
                    this.get();
                    break;
                case "post":
                    this.post(token);
                    break;
                case "postbody":
                    this.postbody(token);
                    break;
            }
        }
        return true;
    }


    private void get() {
        Mono<Pong> response = this.pingApi.restV1PingGet();
        this.processResponse(response);
    }


    private void post(final String token) {
        Mono<Pong> response = this.pingApi.restV1PingPost(token);
        this.processResponse(response);
    }


    private void postbody(final String token) {
        Ping ping = new Ping();
        ping.token(token);

        Mono<Pong> response = this.pingApi.restV1PingbodyPost(ping);
        this.processResponse(response);
    }


    private void processResponse(final Mono<Pong> response) {
        try {
            Pong pong = response.block();
            System.out.printf("Response:%n");
            System.out.printf("    token: %s%n", pong.getToken());
            System.out.printf("    timestamp: %s%n", pong.getTimestamp());
        } catch (Exception ex) {
            System.out.printf("Response exception: %s%n", ex.getMessage());
        }
    }
}
