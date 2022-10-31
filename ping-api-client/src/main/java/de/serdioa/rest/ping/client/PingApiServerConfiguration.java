package de.serdioa.rest.ping.client;

import org.springframework.cloud.loadbalancer.core.ServiceInstanceListSupplier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@Configuration
public class PingApiServerConfiguration {

    @Bean
    public ServiceInstanceListSupplier pingApiServerSupplier() {
        return new PingApiServerSupplier("ping-service");
    }
}
