package de.serdioa.ouath.authserver.token;

import org.springframework.security.oauth2.core.OAuth2Token;


/**
 * Builds an OAuth2 tokens based on the information provided in a context.
 *
 * @param <T> type of tokens created by this builder.
 */
public interface OAuth2TokenBuilder<T extends OAuth2Token> {

    /**
     * Builds an OAuth2 token based on the information provided in a context. Returns {@code null} if this builder does
     * not support the {@link OAuth2TokenContext#getTokenType()}.
     *
     * @param context the context holding information required to build an OAuth2 token.
     * @return the OAuth2 token, or {@code null} if this builder does not support the
     * {@link OAuth2TokenContext#getTokenType()}.
     */
    T build(OAuth2TokenContext context);
}
