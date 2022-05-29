package de.serdioa.ouath.authserver;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.Assert;


/**
 * An {@code AuthenticationConverter} that delegates to a list of {@code AuthenticationConverter}(s).
 * <p>
 * A delegating converter may be configured in a "first-wins" or in an "exclusive" mode. Modes differs in case
 * when more than one delegated {@code AuthenticationConverter} is able to convert the HTTP request into an
 * authentication token. In the "first-wins" mode, the delegating converter returns an authentication token returned by
 * the first delegate which managed to return a non-null token. In the "exclusive" mode an
 * {@code OAuth2AuthenticationException} is thrown if more than one delegate returns a non-null token.
 */
public class OAuth2ClientSecretDelegatingAuthenticationConverter extends OAuth2AbstractAuthenticationConverter {

    private final List<AuthenticationConverter> converters;
    private final boolean exclusive;

    public OAuth2ClientSecretDelegatingAuthenticationConverter(List<AuthenticationConverter> converters) {
        this(converters, false);
    }

    public OAuth2ClientSecretDelegatingAuthenticationConverter(List<AuthenticationConverter> converters, boolean exclusive) {
        Assert.notNull(converters, "converters is required");

        this.converters = converters;
        this.exclusive = exclusive;
    }


    @Override
    public Authentication convert(HttpServletRequest request) {
        Authentication firstAuthentication = null;

        for (AuthenticationConverter converter : this.converters) {
            Authentication authentication = converter.convert(request);
            if (authentication != null) {
                if (exclusive) {
                    // In an exclusive mode we expect only one authentication token.
                    if (firstAuthentication == null) {
                        firstAuthentication = authentication;
                    } else {
                        throw this.invalidRequest("More than 1 authorization scheme in the same request");
                    }
                } else {
                    // In a non-exclusive mode the first authentication token wins.
                    return authentication;
                }
            }
        }

        return firstAuthentication;
    }
}
