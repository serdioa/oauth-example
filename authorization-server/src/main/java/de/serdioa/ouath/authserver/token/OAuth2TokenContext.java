package de.serdioa.ouath.authserver.token;

import java.util.Map;
import java.util.Set;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;


/**
 * A context holds information required to build a OAuth2 token.
 */
public interface OAuth2TokenContext {

    /**
     * Returns the {@code Authentication} that represents the client.
     *
     * @return the {@code Authentication} that represents the client.
     */
    Authentication getAuthentication();


    /**
     * Returns scopes authorized to the client.
     *
     * @return scopes authorized to the client.
     */
    Set<String> getScopes();


    /**
     * Returns custom application-specific claims authorized to the client.
     *
     * @return custom application-specific claims authorized to the client.
     */
    Map<String, Object> getCustomClaims();


    /**
     * Returns a type of the token to build.
     *
     * @return a type of the token to build.
     */
    OAuth2AccessToken.TokenType getTokenType();


    /**
     * Returns the authorization grant type of the token to build.
     *
     * @return the authorization grant type of the token to build.
     */
    AuthorizationGrantType getAuthorizationGrantType();


    static DefaultOAuth2TokenContext.DefaultOAuth2TokenContextBuilder builder() {
        return DefaultOAuth2TokenContext.builder();
    }
}
