package de.serdioa.rest.ping.server.jwt;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;


/**
 * Decoder for JWT tokens based on the Nimbus library.
 */
public class JwtTokenDecoder implements JwtDecoder {

    // A key store holding the key used to sign tokens.
    private final KeyStore keyStore;

    // Configuration properties of this token decoder.
    private final JwtTokenDecoderProperties config;

    // The decoder that parses string representations of tokens and validates them.
    private final JwtDecoder jwtDecoder;


    public JwtTokenDecoder(KeyStore keyStore, JwtTokenDecoderProperties config) throws KeyStoreException {
        Assert.notNull(keyStore, "keyStore cannot be null");
        Assert.notNull(config, "config cannot be null");
        Assert.notEmpty(config.getJwsAlgorithms(), "jwsAlgorithms cannot be null or empty");
        Assert.notEmpty(config.getSignatureKeyIds(), "signatureKeyIds cannot be null or empty");
        Assert.notEmpty(config.getIssuers(), "issuers cannot be null or empty");
        // Audiences are optional.
        Assert.notNull(config.getClockSkew(), "clockSkew cannot be null");

        this.keyStore = keyStore;
        this.config = config;

        // Build the decoder that parses string representations of tokens, and validates tokens.
        JWKSource<SecurityContext> jwkSource = this.buildJwkSource(this.keyStore);
        JWSKeySelector<SecurityContext> jwsKeySelector = this.buildJwsKeySelector(jwkSource);

        DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSKeySelector(jwsKeySelector);

        JWTClaimsSetVerifier<SecurityContext> noopVerifier = (claimsSet, securityContext) -> {
            // Spring Security verifies claims (such as whether the token already expired) independently
            // of the Nimbus library.
        };
        jwtProcessor.setJWTClaimsSetVerifier(noopVerifier);

        NimbusJwtDecoder nimbusJwtDecoder = new NimbusJwtDecoder(jwtProcessor);

        OAuth2TokenValidator<Jwt> jwtValidator = this.buildJwtValidator();
        nimbusJwtDecoder.setJwtValidator(jwtValidator);

        this.jwtDecoder = nimbusJwtDecoder;
    }


    // Returns algorithm for selecting a cryptographic key for verifying a token signature based on the token header.
    private JWSKeySelector<SecurityContext> buildJwsKeySelector(JWKSource<SecurityContext> jwkSource) {
        Set<String> keyIds = this.config.getSignatureKeyIds();
        Set<JWSAlgorithm> algorithms = this.getAlgorithms();
        return new JWSFilterKeySelector<>(keyIds, algorithms, jwkSource);
    }


    // Returns JWS algorithms to be supported.
    private Set<JWSAlgorithm> getAlgorithms() {
        // Transform from Spring enum SignatureAlgorithm to Nimbus pseudo-enum JWSAlgorithm.
        return this.config.getJwsAlgorithms()
                .stream()
                .map(SignatureAlgorithm::name)
                .map(JWSAlgorithm::parse)
                .collect(Collectors.toSet());
    }


    // Builds a JWKSource (a storage of JWK keys) encapsulating the provided key store.
    // A JWKSource instance is required by the JWT encoder implementation library.
    private JWKSource<SecurityContext> buildJwkSource(KeyStore keyStore) throws KeyStoreException {
        JWKSet jwkSet = JWKSet.load(keyStore, null);
        return new ImmutableJWKSet<>(jwkSet);
    }


    @Override
    public Jwt decode(String token) throws JwtException {
        return this.jwtDecoder.decode(token);
    }


    private OAuth2TokenValidator<Jwt> buildJwtValidator() {
        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();

        validators.add(new JwtTimestampValidator(this.config.getClockSkew()));
        validators.add(new JwtIssuerValidator(this.config.getIssuers()));

        // Audience is optional. Add a validator only if the expected audience is configured.
        Set<String> audiences = this.config.getAudiences();
        if (!CollectionUtils.isEmpty(audiences)) {
            validators.add(new JwtAudienceValidator(audiences));
        }

        return new DelegatingOAuth2TokenValidator<>(validators);
    }
}
