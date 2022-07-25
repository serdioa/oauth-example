package de.serdioa.ouath.authserver.jwt;

import java.security.KeyStore;
import java.security.Security;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;
import com.nimbusds.jwt.proc.JWTProcessor;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.JoseHeaderNames;


public class JwtTestSpringSecurity {

    public static void main(String[] args) throws Exception {
        new JwtTestSpringSecurity().run();
    }

    private KeyStoreHolder keyStoreHolder;
    private KeyStoreHolder keyStoreHolderSecond;


    public void run() throws Exception {
        this.setup();

        Jwt jwt = this.buildJwtToken();
        System.out.println("JWT=" + jwt);
        System.out.println("JWT token=" + jwt.getTokenValue());
        this.testJwtTokenNimbus(jwt.getTokenValue());
        this.testJwtTokenSpringSecurity(jwt.getTokenValue());
    }


    private void setup() throws Exception {
        Security.addProvider(BouncyCastleProviderSingleton.getInstance());

        this.keyStoreHolder = new KeyStoreHolder("PKCS12", "BC", "src/config/oauth.pkx", "tiger202206".toCharArray());
        this.keyStoreHolderSecond = new KeyStoreHolder("PKCS12", "BC", "src/config/oauth-second.pkx", "tiger202206"
                .toCharArray());
    }


    private Jwt buildJwtToken() throws Exception {
        JwsHeader.Builder jwsHeaderBuilder = JwsHeader.with(SignatureAlgorithm.RS256)
                .keyId("oauth202206")
                .type("JWT");

        JwtClaimsSet jstClaimsSet = JwtClaimsSet.builder()
                .subject("alice")
                .issuer("sample-issuer")
                .expiresAt(Instant.now().plusSeconds(3600))
                .issuedAt(Instant.now())
                .claim("scope", "aaa bbb ccc")
                .build();

        JwtEncoderParameters jwtEncoderParameters = JwtEncoderParameters.from(jwsHeaderBuilder.build(), jstClaimsSet);

        JWKSource<SecurityContext> jwkSource = this.buildJwkSource(this.keyStoreHolder);
        JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);

        return jwtEncoder.encode(jwtEncoderParameters);
    }


    private JWKSource<SecurityContext> buildJwkSource(KeyStoreHolder keyStoreHolder) throws Exception {
        KeyStore keyStore = keyStoreHolder.getKeyStore();
        JWKSet jwkSet = JWKSet.load(keyStore, null);
        return new ImmutableJWKSet<>(jwkSet);
    }


    public void testJwtTokenNimbus(String token) throws Exception {
        System.out.println("Testing JWT token with Nimbus directly");

        JwtTestNimbusKeystore nimbus = new JwtTestNimbusKeystore();
        nimbus.setup();
        nimbus.testJwtToken(token);
    }


    public void testJwtTokenSpringSecurity(String token) throws Exception {
        System.out.println("Testing JWT token with Spring Security");

        JWTProcessor<SecurityContext> jwtProcessor = this.buildJwtProcessor();
        NimbusJwtDecoder jwtDecoder = new NimbusJwtDecoder(jwtProcessor);

        OAuth2TokenValidator<Jwt> jwtValidator = this.buildOAuth2TokenValidator();
        jwtDecoder.setJwtValidator(jwtValidator);

        Jwt jwt = jwtDecoder.decode(token);

        System.out.println("Headers:");
        Map<String, Object> headers = jwt.getHeaders();
        for (String key : headers.keySet()) {
            Object value = headers.get(key);
            System.out.printf("    %s -> %s (%s)%n", key, value, (value == null ? null : value.getClass()));
        }

        System.out.println("Claims:");
        Map<String, Object> claims = jwt.getClaims();
        for (String key : claims.keySet()) {
            Object value = claims.get(key);
            System.out.printf("    %s -> %s (%s)%n", key, value, (value == null ? null : value.getClass()));
        }
    }


    private JWTProcessor<SecurityContext> buildJwtProcessor() throws Exception {
        DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();

        JWSKeySelector<SecurityContext> jwsKeySelector = this.buildJwsKeySelector();
        jwtProcessor.setJWSKeySelector(jwsKeySelector);

        JWTClaimsSetVerifier<SecurityContext> noopVerifier = (claimsSet, securityContext) -> {
            // Spring Security verifies claims independently of the Nimbus library.
        };
        jwtProcessor.setJWTClaimsSetVerifier(noopVerifier);
        return jwtProcessor;
    }


    private JWSKeySelector<SecurityContext> buildJwsKeySelector() throws Exception {
        Set<JWSAlgorithm> algorithms = Set.of(JWSAlgorithm.RS256);
        JWKSource<SecurityContext> jwkSource = this.buildJwkSource(this.keyStoreHolder);

        return new JWSVerificationKeySelector<>(algorithms, jwkSource);
    }


    private OAuth2TokenValidator<Jwt> buildOAuth2TokenValidator() {
        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        validators.add(new JwtTimestampValidator());
        validators.add(new JwtIssuerValidator("sample-issuer"));

        Set<String> expectedKeyIds = Set.of("oauth202206");

        OAuth2TokenValidator<Jwt> keyIdValidator = jwt -> {
            Map<String, Object> headers = jwt.getHeaders();
            Object keyId = headers.get(JoseHeaderNames.KID);
            System.out.printf("Validator: keyId=%s (%s)%n", keyId, (keyId == null ? null : keyId.getClass()));

            if (keyId == null || !expectedKeyIds.contains(keyId.toString())) {
                OAuth2Error oAuth2Error = this.createOAuth2Error("The key ID is not expected");
                return OAuth2TokenValidatorResult.failure(oAuth2Error);
            }

            return OAuth2TokenValidatorResult.success();
        };
        validators.add(keyIdValidator);

        Set<String> expectedAlgorithms = Set
                .of(SignatureAlgorithm.RS256.toString(), SignatureAlgorithm.RS384.toString());

        OAuth2TokenValidator<Jwt> algorithmValidator = jwt -> {
            Map<String, Object> headers = jwt.getHeaders();
            Object alg = headers.get(JoseHeaderNames.ALG);
            System.out.printf("Validator: alg=%s (%s)%n", alg, (alg == null ? null : alg.getClass()));

            if (alg == null || !expectedAlgorithms.contains(alg.toString())) {
                OAuth2Error oAuth2Error = this.createOAuth2Error("The signature algorithm is not expected");
                return OAuth2TokenValidatorResult.failure(oAuth2Error);
            }

            return OAuth2TokenValidatorResult.success();
        };
        validators.add(algorithmValidator);

        return new DelegatingOAuth2TokenValidator<>(validators);
    }


    private OAuth2Error createOAuth2Error(String reason) {
        return new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, reason,
                "https://tools.ietf.org/html/rfc6750#section-3.1");
    }
}
