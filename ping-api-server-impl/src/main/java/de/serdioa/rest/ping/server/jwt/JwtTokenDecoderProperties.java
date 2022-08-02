package de.serdioa.rest.ping.server.jwt;

import java.time.Duration;
import java.util.HashSet;
import java.util.Set;

import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;

import lombok.Data;


/**
 * Spring configuration properties for {@link JwtTokenDecoder}.
 */
@Data
public class JwtTokenDecoderProperties {

    // Accepted identifier of keys in a key store used to sign tokens. Simultaneously supporting more than one key
    // allows for a smooth replacement of expiring keys.
    private Set<String> signatureKeyIds = new HashSet<>();

    // Accepted signature algorithms used to sign tokens. Simultaneously supporting more than one algorithm allows
    // for a smooth transition when swithing the preferred algorithm.
    private Set<SignatureAlgorithm> jwsAlgorithms = new HashSet<>();

    // Accepted issuers of tokens.
    private Set<String> issuers = new HashSet<>();

    // Accepted audience of tokens. The token is accepted if token's audiences contains any of accepted audiences.
    private Set<String> audiences = new HashSet<>();

    // Maximum accepted clock error. This duration is used as an acceptable error when checking if a token is valid.
    private Duration clockSkew = Duration.ofSeconds(60);
}
