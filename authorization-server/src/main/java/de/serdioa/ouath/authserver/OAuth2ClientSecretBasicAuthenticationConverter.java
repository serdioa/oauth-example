package de.serdioa.ouath.authserver;

import javax.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;


public class OAuth2ClientSecretBasicAuthenticationConverter implements AuthenticationConverter {

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

        throw new UnsupportedOperationException("Not supported yet.");
    }

}
