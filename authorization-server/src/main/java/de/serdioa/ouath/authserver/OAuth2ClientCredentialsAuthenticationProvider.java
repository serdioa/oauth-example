package de.serdioa.ouath.authserver;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Set;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Component;


@Component
public class OAuth2ClientCredentialsAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2ClientCredentialsAuthenticationToken clientCredentialsToken =
                (OAuth2ClientCredentialsAuthenticationToken) authentication;

        Authentication autnentication = new UsernamePasswordAuthenticationToken(
                (String) clientCredentialsToken.getPrincipal(),
                (String) clientCredentialsToken.getCredentials());

        Map<String, Object> additionalParameters = clientCredentialsToken.getAdditionalParameters();

        Instant now = Instant.now();
        Instant expires = now.plus(1, ChronoUnit.HOURS);
        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                "TOKENVALUE",
                now,
                expires,
                Set.of("role_one", "role_two"));

        OAuth2AccessTokenAuthenticationToken authenticationToken =
                new OAuth2AccessTokenAuthenticationToken(autnentication, accessToken, additionalParameters);
        return authenticationToken;
    }


    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2ClientCredentialsAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
