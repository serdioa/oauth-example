package de.serdioa.ouath.authserver;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;

import javax.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.util.StringUtils;


/**
 * Attempts to extract OAuth2 Client Secret request token from a request assuming HTTP Basic authorization.
 */
public class OAuth2ClientSecretBasicAuthenticationConverter extends OAuth2ClientSecretAbstractAuthenticationConverter {

    // The constant for the "Basic" authentication scheme in the HTTP header.
    private static final String AUTHENTICATION_SCHEME_BASIC = "Basic";


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
            throw this.invalidRequest("HTTP header 'Basic' without value");
        }

        byte[] decodedCredentials;
        try {
            byte[] encodedCredentials = headerParts[1].getBytes(StandardCharsets.UTF_8);
            decodedCredentials = Base64.getDecoder().decode(encodedCredentials);
        } catch (IllegalArgumentException ex) {
            throw this.invalidRequest("Value of the HTTP header 'Basic' is not valid Base64");
        }

        String decodedCredentialsString = new String(decodedCredentials, StandardCharsets.UTF_8);
        String[] credentials = decodedCredentialsString.split(":", 2);
        if (credentials.length != 2) {
            throw this
                    .invalidRequest("Value of the HTTP header 'Basic' does not contain separator ':' between client ID and secret");
        }

        String clientId;
        try {
            clientId = URLDecoder.decode(credentials[0], StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ex) {
            throw this
                    .invalidRequest("Client ID in the HTTP header 'Basic' is not valid application/x-www-form-urlencoded");
        }

        String clientSecret;
        try {
            clientSecret = URLDecoder.decode(credentials[1], StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ex) {
            throw this
                    .invalidRequest("Client secret in the HTTP header 'Basic' is not valid application/x-www-form-urlencoded");
        }

        // TODO: add scopes
        return new OAuth2ClientCredentialsAuthenticationToken(clientId, clientSecret,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, Collections.emptySet(), Collections.emptyMap());
    }
}
