package de.serdioa.ouath.authserver.jwt;

import java.time.Instant;
import java.util.Date;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;


/**
 * Test creating and parsing a JWT token using raw Nimbus library.
 */
public class JwtTestNimbusRaw {

    private RSAKey rsaKeyJWK;


    public static void main(String[] args) throws Exception {
        new JwtTestNimbusKeystore().run();
    }


    public void run() throws Exception {
        this.setup();

        String token = this.buildJwtToken();
        System.out.println("JWT token=" + token);
        this.testJwtToken(token);
    }


    private void setup() throws Exception {
        this.rsaKeyJWK = new RSAKeyGenerator(2048)
                .keyID("testrsa")
                .generate();
    }


    private String buildJwtToken() throws Exception {
        JWSSigner signer = new RSASSASigner(this.rsaKeyJWK);
        signer.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject("alice")
                .issuer("sample-issuer")
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .issueTime(Date.from(Instant.now()))
                .claim("scope", "aaa bbb ccc")
                .build();

        SignedJWT signedJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(this.rsaKeyJWK.getKeyID()).build(),
                jwtClaimsSet);

        signedJwt.sign(signer);

        return signedJwt.serialize();
    }


    private void testJwtToken(String token) throws Exception {
        SignedJWT deserializedJwt = SignedJWT.parse(token);
        JWSVerifier jwsVerifier = new RSASSAVerifier(this.rsaKeyJWK.toPublicJWK());
        jwsVerifier.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());

        System.out.println("Verified ? " + deserializedJwt.verify(jwsVerifier));

        System.out.println("Algorithm: " + deserializedJwt.getHeader().getAlgorithm());
        System.out.println("Key ID: " + deserializedJwt.getHeader().getKeyID());
        System.out.println("Subject: " + deserializedJwt.getJWTClaimsSet().getSubject());
        System.out.println("Issuer: " + deserializedJwt.getJWTClaimsSet().getIssuer());
        System.out.println("Issue time: " + deserializedJwt.getJWTClaimsSet().getIssueTime());
        System.out.println("Expiration time: " + deserializedJwt.getJWTClaimsSet().getExpirationTime());
        System.out.println("Scope: " + deserializedJwt.getJWTClaimsSet().getStringClaim("scope"));
    }
}
