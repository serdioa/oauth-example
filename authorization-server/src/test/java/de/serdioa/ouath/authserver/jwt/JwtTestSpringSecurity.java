package de.serdioa.ouath.authserver.jwt;

import java.security.KeyStore;
import java.security.Security;
import java.time.Instant;

import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;


public class JwtTestSpringSecurity {

    public static void main(String[] args) throws Exception {
        new JwtTestSpringSecurity().run();
    }

    private KeyStoreHolder keyStoreHolder;


    public void run() throws Exception {
        this.setup();

        Jwt jwt = this.buildJwtToken();
        System.out.println("JWT=" + jwt);
        System.out.println("JWT token=" + jwt.getTokenValue());
        this.testJwtToken(jwt.getTokenValue());
    }


    private void setup() throws Exception {
        Security.addProvider(BouncyCastleProviderSingleton.getInstance());

        this.keyStoreHolder = new KeyStoreHolder("PKCS12", "BC", "src/config/oauth.pkx", "tiger202206".toCharArray());
    }


    private Jwt buildJwtToken() throws Exception {
        JwsHeader.Builder jwsHeaderBuilder = JwsHeader.with(SignatureAlgorithm.RS256)
                .keyId("oauth202206");

        JwtClaimsSet jstClaimsSet = JwtClaimsSet.builder()
                .subject("alice")
                .issuer("sample-issuer")
                .expiresAt(Instant.now().plusSeconds(3600))
                .issuedAt(Instant.now())
                .claim("scope", "aaa bbb ccc")
                .build();

        JwtEncoderParameters jwtEncoderParameters = JwtEncoderParameters.from(jwsHeaderBuilder.build(), jstClaimsSet);

        JWKSource<SecurityContext> jwkSource = this.buildJwkSource();
        JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);

        return jwtEncoder.encode(jwtEncoderParameters);
    }


    private JWKSource<SecurityContext> buildJwkSource() throws Exception {
        KeyStore keyStore = this.keyStoreHolder.getKeyStore();
        JWKSet jwkSet = JWKSet.load(keyStore, null);
        return new ImmutableJWKSet<>(jwkSet);
    }


    public void testJwtToken(String token) throws Exception {
        JwtTestNimbusKeystore nimbus = new JwtTestNimbusKeystore();
        nimbus.setup();
        nimbus.testJwtToken(token);
    }
}
