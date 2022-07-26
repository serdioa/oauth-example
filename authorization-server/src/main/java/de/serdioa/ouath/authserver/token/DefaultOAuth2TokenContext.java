package de.serdioa.ouath.authserver.token;

import java.util.Map;
import java.util.Set;

import lombok.Builder;
import lombok.Getter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;


/**
 * Default implementation of {@link OAuth2TokenContext}.
 */
@Getter
@Builder
public class DefaultOAuth2TokenContext implements OAuth2TokenContext {

    private final Authentication authentication;

    private final Set<String> scopes;

    private final Map<String, Object> customClaims;

    private final OAuth2AccessToken.TokenType tokenType;

    private final AuthorizationGrantType authorizationGrantType;
}
