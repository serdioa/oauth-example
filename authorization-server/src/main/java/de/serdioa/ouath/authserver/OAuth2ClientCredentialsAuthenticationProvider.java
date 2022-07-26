package de.serdioa.ouath.authserver;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

import de.serdioa.ouath.authserver.token.OAuth2TokenBuilder;
import de.serdioa.ouath.authserver.token.OAuth2TokenContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Component;


/**
 * Spring {@link AuthenticationProvider} that implements OAuth2 Client Credentials grant. This provider accepts a
 * {@link OAuth2ClientCredentialsAuthenticationToken token representing a Client Credentials request}, and returns a
 * {@link OAuth2AccessTokenAuthenticationToken token representing an OAuth2 access grant}.
 */
@Component
public class OAuth2ClientCredentialsAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private OAuth2TokenBuilder<OAuth2AccessToken> tokenBuilder;


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2ClientCredentialsAuthenticationToken clientCredentialsToken =
                (OAuth2ClientCredentialsAuthenticationToken) authentication;

        Set<String> requestedScopes = clientCredentialsToken.getScopes();

        // TODO: validate the client, validate the requested scopes.
        Map<String, Object> customClaims = Collections.emptyMap();

        // Build OAuth2 access token.
        OAuth2TokenContext tokenContext = OAuth2TokenContext.builder()
                .authentication(authentication)
                .scopes(requestedScopes)
                .customClaims(customClaims)
                .tokenType(OAuth2AccessToken.TokenType.BEARER)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();
        OAuth2AccessToken token = this.tokenBuilder.build(tokenContext);

        // Build and return the token with additional information required to properly format the response.
        Map<String, Object> additionalParameters = clientCredentialsToken.getAdditionalParameters();
        return new OAuth2AccessTokenAuthenticationToken(authentication, token, additionalParameters);
    }


    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2ClientCredentialsAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
