package de.serdioa.ouath.authserver.token;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import lombok.Data;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;


/**
 * Spring configuration properties for {@link JwtAccessTokenBuilder}.
 */
@Data
public class JwtAccessTokenBuilderProperties {

    // The identifier of the key in a key store.
    private String signatureKeyId;

    // The cryptographic algorithm used to sign tokens.
    private SignatureAlgorithm jwsAlgorithm;

    // The issuer identifier included in tokens created by this builder.
    private String issuer;

    // The audiences included in tokens created by this builder.
    private List<String> audiences = new ArrayList<>();

    // Lifetime duration of tokens created by this builder.
    private Duration tokenDuration = Duration.ofHours(1);
}
