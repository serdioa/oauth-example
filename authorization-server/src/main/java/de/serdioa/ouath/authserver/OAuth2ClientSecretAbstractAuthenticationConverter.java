package de.serdioa.ouath.authserver;

import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.web.authentication.AuthenticationConverter;


/**
 * An abstract base class for authenticators attempting to extract OAuth2 Client Secret request token from the request.
 */
public abstract class OAuth2ClientSecretAbstractAuthenticationConverter implements AuthenticationConverter {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Setter
    protected OAuth2ExceptionHelper exceptionHelper = new OAuth2ExceptionHelper();


    protected OAuth2AuthenticationException invalidRequest(String description) {
        String id = this.exceptionHelper.nextExceptionId();
        logger.info("{}: {}", id, description);
        return this.exceptionHelper.authenticationException(OAuth2ErrorCodes.INVALID_REQUEST, id, description);
    }
}
