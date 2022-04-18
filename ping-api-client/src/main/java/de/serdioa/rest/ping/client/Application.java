package de.serdioa.rest.ping.client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.Optional;

import de.serdioa.rest.ping.ApiClient;
import de.serdioa.rest.ping.api.PingApi;
import de.serdioa.rest.ping.model.Pong;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import reactor.core.publisher.Mono;


@SpringBootApplication
public class Application implements CommandLineRunner {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    private ApiClient apiClient;
    private PingApi pingApi;

    @Override
    public void run(String... args) throws Exception {
        this.apiClient = new ApiClient();
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

        System.out.printf("Items (%d): %s%n", items.length, Arrays.toString(items));

        if (items.length > 0) {
            switch (items[0]) {
                case "exit":
                    return false;
                case "get":
                    this.get();
                    break;
                case "post":
                    String token = (items.length > 1 ? items[1] : null);
                    this.post(token);
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
