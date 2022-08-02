package de.serdioa.rest.ping.server.jwt;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.util.Assert;


/**
 * Validate that the token audience ("aud") is one of configured values. Configuring multiple values allows for a smooth
 * transition when the audience shall be changed.
 */
public class JwtAudienceValidator extends DelegatingJwtClaimValidator<Object> {

    // Expected issuers. The set may be empty, but it can not be null.
    private final Set<String> audiences;


    public JwtAudienceValidator(Set<String> audiences) {
        super(JwtClaimNames.AUD);

        Assert.notNull(audiences, "audiences cannot be null");
        // Keep immutable copy.
        this.audiences = Collections.unmodifiableSet(new HashSet<>(audiences));
    }


    @Override
    protected boolean isValid(Object audience) {
        // The audience may be either a string, or a collection of strings.
        // If a collection of strings is provided, we consider the audience to be OK as long as at least one of them
        // matches.
        if (audience instanceof Collection) {
            for (Object aud : ((Collection) audience)) {
                if ((aud != null) && this.isAudienceValid(aud.toString())) {
                    return true;
                }
            }
            return false;
        } else {
            return (audience != null) && this.isAudienceValid(audience.toString());
        }
    }


    private boolean isAudienceValid(String audience) {
        // The issuer may be either string or URL. For our purposes, we compare the provided issuer as a string.
        return (audience != null) && this.audiences.contains(audience);
    }
}
