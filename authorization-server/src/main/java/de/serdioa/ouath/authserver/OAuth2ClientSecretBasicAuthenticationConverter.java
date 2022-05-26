package de.serdioa.ouath.authserver;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;

import javax.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;


public class OAuth2ClientSecretBasicAuthenticationConverter implements AuthenticationConverter {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2ClientSecretBasicAuthenticationConverter.class);

    // The constant for the "Basic" authentication scheme in the HTTP header.
    private static final String AUTHENTICATION_SCHEME_BASIC = "Basic";

    private OAuth2ExceptionHelper exceptionHelper = new OAuth2ExceptionHelper();


    @Override
    public Authentication convert(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (!StringUtils.hasText(header)) {
            // Null or empty string.
            return null;
        }

        // If this request is with the authentication scheme "Basic", it is of the form
        // "Basic XXX", where XXX does not contain whitespaces.
        // We have already checked above that the header contains at least one non-whitespace characters,
        // so at least one header part will be available after the split.
        String[] headerParts = header.split("\\s");
        if (!headerParts[0].equalsIgnoreCase(AUTHENTICATION_SCHEME_BASIC)) {
            // This request contains some Authorization header, but not the Basic scheme.
            return null;
        }

        if (headerParts.length != 2) {
            String id = this.exceptionHelper.nextExceptionId();
            logger.info("{}: invalid Authorization header, Basic authorization without value", id);
            throw this.exceptionHelper.authenticationException(OAuth2ErrorCodes.INVALID_REQUEST, id);
        }

        byte[] decodedCredentials;
        try {
            byte[] encodedCredentials = headerParts[1].getBytes(StandardCharsets.UTF_8);
            decodedCredentials = Base64.getDecoder().decode(encodedCredentials);
        } catch (IllegalArgumentException ex) {
            String id = this.exceptionHelper.nextExceptionId();
            logger.info("{}: Basic authorization is not in valid Base64", id);
            throw this.exceptionHelper.authenticationException(OAuth2ErrorCodes.INVALID_REQUEST, id);
        }

        String decodedCredentialsString = new String(decodedCredentials, StandardCharsets.UTF_8);
        String[] credentials = decodedCredentialsString.split(":", 2);
        if (credentials.length != 2) {
            String id = this.exceptionHelper.nextExceptionId();
            logger.info("{}: Basic authorization can not be split on client ID and secret", id);
            throw this.exceptionHelper.authenticationException(OAuth2ErrorCodes.INVALID_REQUEST, id);
        }

        String clientId;
        try {
            clientId = URLDecoder.decode(credentials[0], StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ex) {
            String id = this.exceptionHelper.nextExceptionId();
            logger
                    .info("{}: Basic authorization contains client ID which is not valid application/x-www-form-urlencoded", id);
            throw this.exceptionHelper.authenticationException(OAuth2ErrorCodes.INVALID_REQUEST, id);
        }

        String clientSecret;
        try {
            clientSecret = URLDecoder.decode(credentials[1], StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ex) {
            String id = this.exceptionHelper.nextExceptionId();
            logger
                    .info("{}: Basic authorization contains client secret which is not valid application/x-www-form-urlencoded", id);
            throw this.exceptionHelper.authenticationException(OAuth2ErrorCodes.INVALID_REQUEST, id);
        }

        // TODO: add scopes
        return new OAuth2ClientCredentialsAuthenticationToken(clientId, clientSecret,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, Collections.emptySet(), Collections.emptyMap());
    }
}
