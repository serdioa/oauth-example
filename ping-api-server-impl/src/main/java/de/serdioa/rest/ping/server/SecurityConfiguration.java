package de.serdioa.rest.ping.server;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;


@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        http.authorizeHttpRequests(configurer -> {
//            configurer.antMatchers("/rest/**")
//                    .authenticated();
        http.oauth2ResourceServer(configurer -> {
            configurer.jwt();
        });

        http.authorizeRequests()
                .antMatchers("/swagger-ui/**")
                .permitAll();

        http.csrf().disable();
    }

//    public AuthorizationManager<MethodInvocation> myAuthorizationManager() {
//        return (authenticationSupplier, methodInvocation) -> {
//            System.out.println("Custom authorization manager");
//            Authentication auth = authenticationSupplier.get();
//            System.out.println("    auth=" + auth);
//            System.out.println("    methodInvocation=" + methodInvocation);
//
//            return new AuthorityAuthorizationDecision(true, Collections.emptySet());
//        };
//    }
    // OAuth2ResourceServerConfigurer
//    @Bean(name = BeanIds.AUTHENTICATION_MANAGER)
//    @Override
//    public AuthenticationManager authenticationManagerBean() throws Exception {
//        return super.authenticationManagerBean();
//    }
}
