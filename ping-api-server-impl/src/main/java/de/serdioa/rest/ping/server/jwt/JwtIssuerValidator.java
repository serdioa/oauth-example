package de.serdioa.rest.ping.server.jwt;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.util.Assert;


/**
 * Validate that the token issuer ("iss") is one of configured values. Configuring multiple values allows for a smooth
 * transition when the issuer shall be changed.
 */
public class JwtIssuerValidator extends DelegatingJwtClaimValidator<Object> {

    // Expected issuers. The set may be empty, but it can not be null.
    private final Set<String> issuers;


    public JwtIssuerValidator(Set<String> issuers) {
        super(JwtClaimNames.ISS);

        Assert.notNull(issuers, "issuers cannot be null");
        // Keep immutable copy.
        this.issuers = Collections.unmodifiableSet(new HashSet<>(issuers));
    }


    @Override
    protected boolean isValid(Object issuer) {
        // The issuer may be either string or URL. For our purposes, we compare the provided issuer as a string.
        return (issuer != null) && this.issuers.contains(issuer.toString());
    }
}
