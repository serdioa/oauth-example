package de.serdioa.rest.ping.server.jwt;

import java.security.KeyStore;
import java.security.KeyStoreException;

import de.serdioa.spring.crypto.keystore.KeyStoreFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


/**
 * Spring Boot configuration for authentication based on JWT tokens.
 */
@Configuration
public class JwtAuthenticationConfig {

    @Bean
    @ConfigurationProperties(prefix = "spring.security.oauth2.resourceserver.keystore")
    public KeyStoreFactory oauth2KeyStore() {
        return new KeyStoreFactory();
    }


    @Bean
    @ConfigurationProperties(prefix = "spring.security.oauth2.resourceserver.jwt")
    public JwtTokenDecoderProperties jwtTokenDecoderProperties() {
        return new JwtTokenDecoderProperties();
    }


    @Bean
    public JwtTokenDecoder jwtTokenDecoder(KeyStore oauth2KeyStore,
            JwtTokenDecoderProperties jwtTokenDecoderProperties) throws KeyStoreException {
        return new JwtTokenDecoder(oauth2KeyStore, jwtTokenDecoderProperties);
    }
}
