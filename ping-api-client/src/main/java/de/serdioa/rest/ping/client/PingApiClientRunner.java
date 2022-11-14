package de.serdioa.rest.ping.client;

import java.util.concurrent.atomic.AtomicInteger;

import de.serdioa.rest.generated.ping.client.api.PingApi;
import de.serdioa.rest.generated.ping.client.model.Ping;
import de.serdioa.rest.generated.ping.client.model.Pong;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;


@Component
public class PingApiClientRunner {

    private final AtomicInteger requestCounter = new AtomicInteger();

    @Autowired
    private PingApi pingApi;


    @Scheduled(fixedDelay = 5000)
    public void sendRequest() {
        int count = this.requestCounter.getAndIncrement();
        switch (count % 3) {
            case 0:
                this.pingGet(count);
                break;
            case 1:
                this.pingPost(count);
                break;
            default:
                this.pingbodyPost(count);
        }
    }


    private void pingGet(int count) {
        final Mono<Pong> response = this.pingApi.restV1PingGet();
        response.subscribe(pong -> System.out.printf("Ping GET received response: %s\n", pong),
                ex -> {
                    System.out.printf("Ping GET received exception: %s\n", ex);
                    ex.printStackTrace();
                });
    }


    private void pingPost(int count) {
        final String token = "ping-" + count;
        final Mono<Pong> response = this.pingApi.restV1PingPost(token);
        response.subscribe(pong -> System.out.printf("Ping POST received response: %s\n", pong),
                ex -> {
                    System.out.printf("Ping POST received exception: %s\n", ex);
                    ex.printStackTrace();
                });
    }


    private void pingbodyPost(int count) {
        final String token = "ping-" + count;
        final Ping request = new Ping();
        request.setToken(token);

        final Mono<Pong> response = this.pingApi.restV1PingbodyPost(request);
        response.subscribe(pong -> System.out.printf("Pingbody POST received response: %s\n", pong),
                ex -> {
                    System.out.printf("Pingbody POST received exception: %s\n", ex);
                    ex.printStackTrace();
                });
    }
}
