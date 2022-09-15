package de.serdioa.rest.ping.client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import de.serdioa.rest.generated.ping.client.ApiClient;
import de.serdioa.rest.generated.ping.client.api.PingApi;
import de.serdioa.rest.generated.ping.client.model.Ping;
import de.serdioa.rest.generated.ping.client.model.Pong;

import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.api.Request;
import org.eclipse.jetty.http.HttpField;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.http.client.reactive.JettyClientHttpConnector;
import org.springframework.security.oauth2.client.AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.InMemoryReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;


// https://andrew-flower.com/blog/webclient-body-logging
// https://dev.to/stevenpg/logging-with-spring-webclient-2j6o
public class ApplicationJetty implements CommandLineRunner {

    private ApiClient apiClient;
    private PingApi pingApi;


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

        SslContextFactory.Client sslContextFactory = new SslContextFactory.Client();
        HttpClient httpClient = new HttpClient(sslContextFactory) {
            @Override
            public Request newRequest(URI uri) {
                Request request = super.newRequest(uri);
                return enhance(request);
            }
        };

        WebClient webClient = WebClient.builder()
                //                .filter(new VerboseExchangeFilterFunction())
                .filter(oauth)
                .clientConnector(new JettyClientHttpConnector(httpClient))
                .build();

        this.apiClient = new ApiClient(webClient);
        this.apiClient.setBasePath("http://localhost:8080");

        this.pingApi = new PingApi(this.apiClient);

        while (this.parseAndProcessCommand()) {
            // Main command-processing loop.
        }
    }


    private Request enhance(Request inboundRequest) {
        StringBuilder logRequest = new StringBuilder();
        StringBuilder logResponse = new StringBuilder();
        // Request Logging
        inboundRequest.onRequestBegin(request
                -> logRequest.append("Request: \n")
                        .append("URI: ")
                        .append(request.getURI())
                        .append("\n")
                        .append("Method: ")
                        .append(request.getMethod()));
        inboundRequest.onRequestHeaders(request -> {
            logRequest.append("\nHeaders:\n");
            for (HttpField header : request.getHeaders()) {
                logRequest.append("\t\t" + header.getName() + " : " + header.getValue() + "\n");
            }
        });
        inboundRequest.onRequestContent((request, content) -> {
            String bufferAsString = StandardCharsets.UTF_8.decode(content).toString();
            logRequest.append("Request Body:\n" + bufferAsString);
        });

        // Response Logging
        inboundRequest.onResponseBegin(response
                -> logResponse.append("Response:\n")
                        .append("Status: ")
                        .append(response.getStatus())
                        .append("\n"));
        inboundRequest.onResponseHeaders(response -> {
            logResponse.append("Headers:\n");
            for (HttpField header : response.getHeaders()) {
                logResponse.append("\t\t" + header.getName() + " : " + header.getValue() + "\n");
            }
        });
        inboundRequest.onResponseContent(((response, content) -> {
            String bufferAsString = StandardCharsets.UTF_8.decode(content).toString();
            logResponse.append("Response Body:\n" + bufferAsString);
        }));

        // Add actual log invocation
        inboundRequest.onRequestSuccess(request -> {
            String msg = "!!! onRequestSuccess: \n" + logRequest;
            System.out.println(msg);
        });
        inboundRequest.onResponseSuccess(response -> {
            String msg = "!!! onResponseSuccess: \n" + logResponse;
            System.out.println(msg);
        });

        // Return original request
        return inboundRequest;
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
