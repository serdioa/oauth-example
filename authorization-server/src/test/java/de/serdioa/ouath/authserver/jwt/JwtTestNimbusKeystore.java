package de.serdioa.ouath.authserver.jwt;

import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;


/**
 * Test creating and parsing a JWT token using Nimbus library with a Java Security key store.
 */
public class JwtTestNimbusKeystore {

    private KeyStoreHolder keyStoreHolder;


    public static void main(String[] args) throws Exception {
        new JwtTestNimbusKeystore().run();
    }


    public void run() throws Exception {
        this.setup();

        String token = this.buildJwtToken();
        System.out.println("JWT token=" + token);
        this.testJwtToken(token);
    }


    public void setup() throws Exception {
        Security.addProvider(BouncyCastleProviderSingleton.getInstance());

        this.keyStoreHolder = new KeyStoreHolder("PKCS12", "BC", "src/config/oauth.pkx", "tiger202206".toCharArray());

        X509Certificate cert = this.keyStoreHolder.getCertificate("oauth202206");
        System.out.println("cert:");
        System.out.println("    sigAlg: " + cert.getSigAlgName());
        System.out.println("    notBefore: " + cert.getNotBefore());
        System.out.println("    notAfter: " + cert.getNotBefore());

        PrivateKey key = this.keyStoreHolder.getPrivateKey("oauth202206", "tiger202206".toCharArray());
        System.out.println("key:");
        System.out.println("    alg: " + key.getAlgorithm());
    }


    public String buildJwtToken() throws Exception {
        String keyId = "oauth202206";
        PrivateKey key = this.keyStoreHolder.getPrivateKey(keyId, "tiger202206".toCharArray());

        JWSSigner signer = new RSASSASigner(key);
        signer.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject("alice")
                .issuer("sample-issuer")
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .issueTime(Date.from(Instant.now()))
                .claim("scope", "aaa bbb ccc")
                .build();

        SignedJWT signedJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(keyId).build(),
                jwtClaimsSet);

        signedJwt.sign(signer);

        return signedJwt.serialize();
    }


    public void testJwtToken(String token) throws Exception {
        X509Certificate cert = this.keyStoreHolder.getCertificate("oauth202206");
        RSAPublicKey key = (RSAPublicKey) cert.getPublicKey();

        SignedJWT deserializedJwt = SignedJWT.parse(token);
        JWSVerifier jwsVerifier = new RSASSAVerifier(key);
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
