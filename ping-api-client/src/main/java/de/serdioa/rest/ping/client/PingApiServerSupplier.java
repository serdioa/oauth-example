package de.serdioa.rest.ping.client;

import java.util.List;
import java.util.Arrays;

import lombok.AllArgsConstructor;
import org.springframework.cloud.client.DefaultServiceInstance;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.loadbalancer.core.ServiceInstanceListSupplier;
import reactor.core.publisher.Flux;


@AllArgsConstructor
public class PingApiServerSupplier implements ServiceInstanceListSupplier {

    private final String serviceId;


    @Override
    public String getServiceId() {
        return this.serviceId;
    }


    @Override
    public Flux<List<ServiceInstance>> get() {
        return Flux.just(Arrays.asList(
                new DefaultServiceInstance(this.serviceId + "-1", this.serviceId, "localhost", 8080, false),
                new DefaultServiceInstance(this.serviceId + "-2", this.serviceId, "localhost", 8081, false)
        ));
    }
}
