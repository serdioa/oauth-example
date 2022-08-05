package de.serdioa.ouath.authserver;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;


@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/oauth2/**")
                .permitAll();

        http.csrf().disable();

        // Enable CORS (Cross-Origin Resource Sharing) to make possible to call the OAuth2 endpoints from Swagger
        // hosted on a different host or port. The CORS configuration is provided by the method
        // Application.corsConfigurer().
        http.cors();
    }


    // By default the Spring Authentication Manager is used internally, but is not available as a Spring Bean.
    // Configure Spring to register the Authentication Manager is a Spring Bean, so that it may be injected in other
    // beans.
    @Bean(name = BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
