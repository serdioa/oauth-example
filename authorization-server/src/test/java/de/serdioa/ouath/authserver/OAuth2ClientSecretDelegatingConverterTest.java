package de.serdioa.ouath.authserver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;


public class OAuth2ClientSecretDelegatingConverterTest {

    private MockHttpServletRequest request;

    private OAuth2ClientSecretBasicAuthenticationConverter basicConverter;
    private OAuth2ClientSecretPostAuthenticationConverter postConverter;
    private OAuth2ClientSecretDelegatingAuthenticationConverter delegatingConverter;


    @BeforeEach
    public void setUp() {
        // Configuration applies to most tests.
        // Those few tests which are an exception, has to reset the header.
        this.request = new MockHttpServletRequest();
        this.request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue());

        this.basicConverter = new OAuth2ClientSecretBasicAuthenticationConverter();
        this.postConverter = new OAuth2ClientSecretPostAuthenticationConverter();
        this.delegatingConverter = new OAuth2ClientSecretDelegatingAuthenticationConverter(
                Arrays.asList(this.basicConverter, this.postConverter), true);
    }


    private static String encodeBase64(String str) {
        byte[] stringBytes = str.getBytes(StandardCharsets.UTF_8);
        byte[] encodedBytes = Base64.getEncoder().encode(stringBytes);
        return new String(encodedBytes, StandardCharsets.UTF_8);
    }


    private void configureBasic(final boolean success) {
        if (success) {
            // Configure valid Basic authorization.
            String authorization = encodeBase64("aBc:DeF");
            this.request.addHeader(HttpHeaders.AUTHORIZATION, "Basic " + authorization);
        } else {
            // Configure invalid Basic authorization: the value of the header is missing.
            this.request.addHeader(HttpHeaders.AUTHORIZATION, "Basic");
        }
    }


    private void configurePost(final boolean success) {
        if (success) {
            // Configure valid Post authorization.
            this.request.addParameter(OAuth2ParameterNames.CLIENT_ID, "aBc");
            this.request.addParameter(OAuth2ParameterNames.CLIENT_SECRET, "DeF");
        } else {
            // Configure invalid Post authorization: the client ID is provided more than once.
            this.request.addParameter(OAuth2ParameterNames.CLIENT_ID, "aBc");
            this.request.addParameter(OAuth2ParameterNames.CLIENT_ID, "xYz");
        }
    }


    // Successfull basic authentication.
    @Test
    public void testConvertBasicSucceed() {
        this.configureBasic(true);
        this.request.addParameter(OAuth2ParameterNames.SCOPE, "scope_A scope_B scope_C");

        OAuth2ClientCredentialsAuthenticationToken token =
                (OAuth2ClientCredentialsAuthenticationToken) this.delegatingConverter.convert(this.request);

        assertEquals("aBc", token.getPrincipal());
        assertEquals("DeF", token.getCredentials());
        assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, token.getClientAuthenticationMethod());
        assertEquals(Set.of("scope_A", "scope_B", "scope_C"), token.getScopes());
    }


    // Failed basic authentication.
    @Test
    public void testConvertBasicFailed() {
        this.configureBasic(false);
        this.request.addParameter(OAuth2ParameterNames.SCOPE, "scope_A scope_B scope_C");

        OAuth2AuthenticationException ex = assertThrows(OAuth2AuthenticationException.class, () -> {
            this.delegatingConverter.convert(this.request);
        });

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, ex.getError().getErrorCode());
    }


    // Successfull post authentication.
    @Test
    public void testConvertPostSucceed() {
        this.configurePost(true);
        this.request.addParameter(OAuth2ParameterNames.SCOPE, "scope_A scope_B scope_C");

        OAuth2ClientCredentialsAuthenticationToken token =
                (OAuth2ClientCredentialsAuthenticationToken) this.delegatingConverter.convert(this.request);

        assertEquals("aBc", token.getPrincipal());
        assertEquals("DeF", token.getCredentials());
        assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_POST, token.getClientAuthenticationMethod());
        assertEquals(Set.of("scope_A", "scope_B", "scope_C"), token.getScopes());
    }


    // Failed post authentication.
    @Test
    public void testConvertPostFailed() {
        this.configurePost(false);
        this.request.addParameter(OAuth2ParameterNames.SCOPE, "scope_A scope_B scope_C");

        OAuth2AuthenticationException ex = assertThrows(OAuth2AuthenticationException.class, () -> {
            this.delegatingConverter.convert(this.request);
        });

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, ex.getError().getErrorCode());
    }


    // Both basic and post authentication successfull.
    @Test
    public void testConvertBothSucceed() {
        this.configureBasic(true);
        this.configurePost(true);
        this.request.addParameter(OAuth2ParameterNames.SCOPE, "scope_A scope_B scope_C");

        OAuth2AuthenticationException ex = assertThrows(OAuth2AuthenticationException.class, () -> {
            this.delegatingConverter.convert(this.request);
        });

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, ex.getError().getErrorCode());
    }
}
