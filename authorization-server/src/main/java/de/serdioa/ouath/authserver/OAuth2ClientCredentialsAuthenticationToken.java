package de.serdioa.ouath.authserver;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.util.Assert;


/**
 * An authentication token representing a Client Credentials Grant request to the OAuth2 server (RFC 6749, 4.4).
 */
public class OAuth2ClientCredentialsAuthenticationToken extends AbstractAuthenticationToken {

    private final Authentication clientPrincipal;
    private final ClientAuthenticationMethod clientAuthenticationMethod;
    private final Set<String> scopes;
    private final Map<String, Object> additionalParameters;


    public OAuth2ClientCredentialsAuthenticationToken(Authentication clientPrincipal,
            ClientAuthenticationMethod clientAuthenticationMethod, final Set<String> scopes,
            Map<String, Object> additionalParameters) {
        super(Collections.emptyList());

        Assert.notNull(clientPrincipal, "clientPrincipal is required");
        Assert.notNull(clientAuthenticationMethod, "clientAuthenticationMethod is required");
        Assert.notNull(scopes, "scopes is required");
        Assert.notNull(additionalParameters, "additionalParameters is required");

        this.clientPrincipal = clientPrincipal;
        this.clientAuthenticationMethod = clientAuthenticationMethod;
        this.scopes = Collections.unmodifiableSet(new HashSet<>(scopes));
        this.additionalParameters = Collections.unmodifiableMap(new HashMap<>(additionalParameters));
    }


    @Override
    public Object getPrincipal() {
        return this.clientPrincipal.getPrincipal();
    }


    @Override
    public Object getCredentials() {
        return this.clientPrincipal.getCredentials();
    }


    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        if (this.clientPrincipal instanceof CredentialsContainer) {
            ((CredentialsContainer) this.clientPrincipal).eraseCredentials();
        }
    }


    public Set<String> getScopes() {
        return this.scopes;
    }


    public Map<String, Object> getAdditionalParameters() {
        return this.additionalParameters;
    }


    public ClientAuthenticationMethod getClientAuthenticationMethod() {
        return this.clientAuthenticationMethod;
    }
}
