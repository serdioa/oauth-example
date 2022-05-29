package de.serdioa.ouath.authserver;

import java.util.Collections;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;


/**
 * An abstract base class for authenticators attempting to extract OAuth2 Client Secret request token from the request.
 */
public abstract class OAuth2ClientSecretAbstractAuthenticationConverter implements AuthenticationConverter {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Setter
    protected OAuth2ExceptionHelper exceptionHelper = new OAuth2ExceptionHelper();


    @Override
    public Authentication convert(HttpServletRequest request) {
        String[] grantTypeValues = request.getParameterValues(OAuth2ParameterNames.GRANT_TYPE);
        if (grantTypeValues == null) {
            // This request is not for any grant type.
            return null;
        }
        if (grantTypeValues.length != 1) {
            throw invalidRequest("More than 1 request parameter 'grant_type'");
        }
        if (!AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(grantTypeValues[0])) {
            // This request is not for a client credentials.
            return null;
        }

        Authentication clientPrincipal = this.convertClientPrincipal(request);
        if (clientPrincipal == null) {
            // The request does not contain client principal supported by this converter.
            return null;
        }

        ClientAuthenticationMethod authenticationMethod = this.getClientAuthenticationMethod();
        Set<String> scopes = this.convertScopes(request);

        return new OAuth2ClientCredentialsAuthenticationToken(clientPrincipal, authenticationMethod,
                scopes, Collections.emptyMap());
    }


    protected abstract ClientAuthenticationMethod getClientAuthenticationMethod();


    protected abstract Authentication convertClientPrincipal(HttpServletRequest request);


    protected Set<String> convertScopes(HttpServletRequest request) {
        return Collections.emptySet();
    }


    protected OAuth2AuthenticationException invalidRequest(String description) {
        String id = this.exceptionHelper.nextExceptionId();
        logger.info("{}: {}", id, description);
        return this.exceptionHelper.authenticationException(OAuth2ErrorCodes.INVALID_REQUEST, id, description);
    }
}
