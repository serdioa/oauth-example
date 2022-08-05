package de.serdioa.rest.ping.server;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;


@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.oauth2ResourceServer(configurer -> {
            configurer.jwt();
        });

        http.authorizeRequests()
                .antMatchers("/swagger-ui/**")
                .permitAll();

        http.csrf().disable();

        // Enable CORS (Cross-Origin Resource Sharing) to make possible to call the OAuth2 endpoints from Swagger
        // hosted on a different host or port. The CORS configuration is provided by the method
        // Application.corsConfigurer().
        http.cors();
    }
}
