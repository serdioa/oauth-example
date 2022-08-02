package de.serdioa.ouath.authserver.token;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;


/**
 * Builds JWT OAuth2 Access Token based on the information provided in a context.
 */
public class JwtAccessTokenBuilder implements OAuth2TokenBuilder<OAuth2AccessToken> {

    // A constant for the header property "typ" of created tokens.
    private static final String TOKEN_HEADER_TYPE = "JWT";

    // A key store holding the key used to sign tokens.
    private final KeyStore keyStore;

    // Configuration properties of this token builder.
    private final JwtAccessTokenBuilderProperties config;

    // The encoder that formats string representations of tokens.
    private final JwtEncoder jwtEncoder;

    // The same header is used to build all tokens, so we may cache and share it.
    private final JwsHeader jwsHeader;


    public JwtAccessTokenBuilder(KeyStore keyStore, JwtAccessTokenBuilderProperties config) throws KeyStoreException {
        Assert.notNull(keyStore, "keyStore cannot be null");
        Assert.notNull(config, "config cannot be null");
        Assert.notNull(config.getJwsAlgorithm(), "jwsAlgorithm cannot be null");
        Assert.notNull(config.getSignatureKeyId(), "signatureKeyId cannot be null");
        Assert.notNull(config.getIssuer(), "issuer cannot be null");
        Assert.notNull(config.getTokenDuration(), "tokenDuration cannot be null");
        // The property "audiences" is optional.

        this.keyStore = keyStore;
        this.config = config;

        // Build the encoder that formats string representation of tokens.
        JWKSource<SecurityContext> jwkSource = this.buildJwkSource(this.keyStore);
        this.jwtEncoder = new NimbusJwtEncoder(jwkSource);

        // Cache the shared JWT token header.
        this.jwsHeader = JwsHeader.with(config.getJwsAlgorithm())
                .keyId(config.getSignatureKeyId())
                .type(TOKEN_HEADER_TYPE)
                .build();
    }


    // Builds a JWKSource (a storage of JWK keys) encapsulating the provided key store.
    // A JWKSource instance is required by the JWT encoder implementation library.
    private JWKSource<SecurityContext> buildJwkSource(KeyStore keyStore) throws KeyStoreException {
        JWKSet jwkSet = JWKSet.load(keyStore, null);
        return new ImmutableJWKSet<>(jwkSet);
    }


    @Override
    public OAuth2AccessToken build(OAuth2TokenContext context) {
        Instant now = Instant.now();

        Consumer<Map<String, Object>> claimsCustomizer = this.buildClaimsCustomizer(context);

        JwtClaimsSet.Builder jwtClaimsSetBuilder = JwtClaimsSet.builder()
                .id(UUID.randomUUID().toString())
                .subject(context.getAuthentication().getName())
                .issuer(config.getIssuer())
                .issuedAt(now)
                .notBefore(now)
                .expiresAt(now.plus(config.getTokenDuration()))
                .claims(claimsCustomizer);

        // The property "audiences" is optional.
        List<String> audiences = this.config.getAudiences();
        if (!CollectionUtils.isEmpty(audiences)) {
            jwtClaimsSetBuilder.audience(audiences);
        }

        JwtClaimsSet jwtClaimsSet = jwtClaimsSetBuilder.build();

        JwtEncoderParameters jwtEncoderParameters = JwtEncoderParameters.from(this.jwsHeader, jwtClaimsSet);
        Jwt jwt = this.jwtEncoder.encode(jwtEncoderParameters);

        return new OAuth2AccessToken(context.getTokenType(), jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt(),
                context.getScopes());
    }


    private Consumer<Map<String, Object>> buildClaimsCustomizer(OAuth2TokenContext context) {
        return claims -> {
            // Add the authorized scope.
            String scope = this.formatScope(context.getScopes());
            claims.put(OAuth2ParameterNames.SCOPE, scope);

            // Add custom claims, making sure to not overwrite standard (already present) claims.
            if (context.getCustomClaims() != null) {
                context.getCustomClaims().forEach((claim, value) -> {
                    claims.putIfAbsent(claim, value);
                });
            }
        };
    }


    private String formatScope(Set<String> scopes) {
        if (scopes == null || scopes.isEmpty()) {
            return "";
        } else {
            return String.join(" ", scopes);
        }
    }
}
