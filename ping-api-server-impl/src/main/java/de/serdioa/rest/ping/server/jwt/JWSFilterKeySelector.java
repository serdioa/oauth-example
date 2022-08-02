package de.serdioa.rest.ping.server.jwt;

import java.util.Set;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;


/**
 * Selects a key to verify JWS objects, validating signature algorithm and key ID against configured white-lists.
 *
 * @param <C> the type of the security context.
 */
public class JWSFilterKeySelector<C extends SecurityContext> extends JWSVerificationKeySelector<C> {

    private final Set<String> keyIds;


    public JWSFilterKeySelector(Set<String> keyIds, Set<JWSAlgorithm> jwsAlgs, JWKSource<C> jwkSource) {
        super(jwsAlgs, jwkSource);

        if (keyIds == null) {
            throw new IllegalArgumentException("keyIds cannot be null");
        }
        this.keyIds = keyIds;
    }


    @Override
    protected JWKMatcher createJWKMatcher(final JWSHeader jwsHeader) {
        if (!this.isKeyAllowed(jwsHeader.getKeyID())) {
            return null;
        } else {
            return super.createJWKMatcher(jwsHeader);
        }
    }


    public boolean isKeyAllowed(String keyId) {
        return this.keyIds.contains(keyId);
    }
}
