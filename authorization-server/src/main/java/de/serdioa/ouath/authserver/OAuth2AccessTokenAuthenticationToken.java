package de.serdioa.ouath.authserver;

import java.util.Collections;
import java.util.Map;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.util.Assert;


/**
 * An authentication token representing a granted OAuth2 token.
 */
public class OAuth2AccessTokenAuthenticationToken extends AbstractAuthenticationToken {

    private final Authentication principal;
    private final OAuth2AccessToken accessToken;
    private final Map<String, Object> additionalParameters;


    public OAuth2AccessTokenAuthenticationToken(Authentication principal, OAuth2AccessToken accessToken) {
        this(principal, accessToken, Collections.emptyMap());
    }


    public OAuth2AccessTokenAuthenticationToken(Authentication principal, OAuth2AccessToken accessToken,
            Map<String, Object> additionalParameters) {
        super(principal.getAuthorities());

        Assert.notNull(accessToken, "accessToken is required");
        Assert.notNull(additionalParameters, "additionalParameters is required");

        this.principal = principal;
        this.accessToken = accessToken;
        this.additionalParameters = additionalParameters;
    }


    @Override
    public Object getCredentials() {
        return this.principal.getCredentials();
    }


    @Override
    public Object getPrincipal() {
        return this.principal;
    }


    public OAuth2AccessToken getAccessToken() {
        return this.accessToken;
    }


    public Map<String, Object> getAdditionalParameters() {
        return this.additionalParameters;
    }
}
