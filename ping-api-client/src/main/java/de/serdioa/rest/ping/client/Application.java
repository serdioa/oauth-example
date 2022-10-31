package de.serdioa.rest.ping.client;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;


// https://andrew-flower.com/blog/webclient-body-logging
// https://dev.to/stevenpg/logging-with-spring-webclient-2j6o
// @SpringBootApplication
public class Application implements CommandLineRunner {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }


    @Override
    public void run(String... args) throws Exception {
//        new ApplicationSpringBoot().run(args);
    }
}
