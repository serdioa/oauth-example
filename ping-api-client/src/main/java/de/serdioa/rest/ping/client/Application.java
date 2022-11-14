package de.serdioa.rest.ping.client;

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.scheduling.annotation.EnableScheduling;


// https://andrew-flower.com/blog/webclient-body-logging
// https://dev.to/stevenpg/logging-with-spring-webclient-2j6o
@EnableScheduling
@SpringBootApplication
public class Application {
    
    public static void main(String[] args) throws Exception {
        new SpringApplicationBuilder(Application.class)
                .web(WebApplicationType.NONE)
                .build()
                .run(args);
        
        Thread.sleep(Long.MAX_VALUE);
    }
}
