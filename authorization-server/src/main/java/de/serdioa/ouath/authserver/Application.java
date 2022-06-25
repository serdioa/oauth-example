package de.serdioa.ouath.authserver;

import de.serdioa.spring.crypto.keystore.KeyStoreFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;


@SpringBootApplication
@ComponentScan(basePackages = {"de.serdioa.ouath.authserver"})
@Configuration
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }


    @Bean
    public ApplicationContextPrinter applicationContextPrinter() {
        return new ApplicationContextPrinter();
    }


    @Bean
    public OAuth2ExceptionHelper oauth2ExceptionHelper() {
        return new OAuth2ExceptionHelper();
    }


    @Bean
    @ConfigurationProperties(prefix = "security.keystore.oauth2")
    public KeyStoreFactory oauth2KeyStore() {
        return new KeyStoreFactory();
    }
}
