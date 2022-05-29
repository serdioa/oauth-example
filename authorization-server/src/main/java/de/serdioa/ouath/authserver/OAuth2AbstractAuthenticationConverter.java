package de.serdioa.ouath.authserver;

import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.web.authentication.AuthenticationConverter;


public abstract class OAuth2AbstractAuthenticationConverter implements AuthenticationConverter {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Setter
    protected OAuth2ExceptionHelper exceptionHelper = new OAuth2ExceptionHelper();


    protected OAuth2AuthenticationException invalidRequest(String description) {
        return this.exceptionHelper.authenticationException(this.logger, OAuth2ErrorCodes.INVALID_REQUEST, description);
    }
}
