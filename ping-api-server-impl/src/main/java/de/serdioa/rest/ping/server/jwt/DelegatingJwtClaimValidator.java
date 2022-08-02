package de.serdioa.rest.ping.server.jwt;

import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;


/**
 * Validates claims of JWT token by defining a validation method and delegating to a {@link JwtClaimValidator}.
 *
 * @param <T> the type of the claim value to be validated.
 */
public abstract class DelegatingJwtClaimValidator<T> implements OAuth2TokenValidator<Jwt> {

    // The delegate validator.
    private final JwtClaimValidator<T> validator;


    public DelegatingJwtClaimValidator(String claim) {
        this.validator = new JwtClaimValidator<>(claim, this::isValid);
    }


    protected abstract boolean isValid(T value);


    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        return this.validator.validate(token);
    }
}
