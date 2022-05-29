package de.serdioa.ouath.authserver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;


public class OAuth2ClientSecretBasicAuthenticationConverterTest {

    private MockHttpServletRequest request;
    private OAuth2ClientSecretBasicAuthenticationConverter converter;


    @BeforeEach
    public void setUp() {
        // Configuration applies to most tests.
        // Those few tests which are an exception, has to reset the header.
        this.request = new MockHttpServletRequest();
        this.request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue());

        this.converter = new OAuth2ClientSecretBasicAuthenticationConverter();
    }


    private static String encodeBase64(String str) {
        byte[] stringBytes = str.getBytes(StandardCharsets.UTF_8);
        byte[] encodedBytes = Base64.getEncoder().encode(stringBytes);
        return new String(encodedBytes, StandardCharsets.UTF_8);
    }


    // The request parameter "grant_type" is missing.
    @Test
    public void testConverterNoGrantType() {
        this.request.removeParameter(OAuth2ParameterNames.GRANT_TYPE);
        assertNull(this.converter.convert(this.request));
    }


    // The request parameter "grant_type" differs from "client_credentials".
    @Test
    public void testConverterUnsupportedGrantType() {
        this.request.removeParameter(OAuth2ParameterNames.GRANT_TYPE);
        this.request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.REFRESH_TOKEN.getValue());
        assertNull(this.converter.convert(this.request));
    }


    // The request parameter "grant_type" appears more then once.
    @Test
    public void testConverterMultipleGrantType() {
        this.request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.REFRESH_TOKEN.getValue());

        OAuth2AuthenticationException ex = assertThrows(OAuth2AuthenticationException.class, () -> {
            this.converter.convert(this.request);
        });

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, ex.getError().getErrorCode());
    }


    // There is no "Authorization" header at all: not an error, but the converter can not extract authentication
    // information from the request, and returns null.
    @Test
    public void testConvertNoAuthorizationHeader() {
        assertNull(this.converter.convert(this.request));
    }


    @Test
    public void testConvertMultipleAuthorizationHeaders() {
        String firstAuthorization = encodeBase64("aBc:DeF");
        this.request.addHeader(HttpHeaders.AUTHORIZATION, "Basic " + firstAuthorization);

        String secondAuthorization = encodeBase64("gHi:JkL");
        this.request.addHeader(HttpHeaders.AUTHORIZATION, "Basic " + secondAuthorization);

        OAuth2AuthenticationException ex = assertThrows(OAuth2AuthenticationException.class, () -> {
            this.converter.convert(this.request);
        });

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, ex.getError().getErrorCode());
    }


    // There is "Authorization" header, but it is not a "Basic" authorization.
    // The converter can not extract authentication information from the request, and returns null.
    @Test
    public void testConverterDifferentAuhorizationScheme() {
        this.request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer abc");
        assertNull(this.converter.convert(this.request));
    }


    // There is an "Authorization" header with the "Basic" authorization, but no value is available.
    @Test
    public void testConverterNoValue() {
        this.request.addHeader(HttpHeaders.AUTHORIZATION, "Basic");

        OAuth2AuthenticationException ex = assertThrows(OAuth2AuthenticationException.class, () -> {
            this.converter.convert(this.request);
        });

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, ex.getError().getErrorCode());
    }


    // The "Basic" authentication is not in Base64 encoding.
    @Test
    public void testConverterInvalidBase64() {
        this.request.addHeader(HttpHeaders.AUTHORIZATION, "Basic ~");

        OAuth2AuthenticationException ex = assertThrows(OAuth2AuthenticationException.class, () -> {
            this.converter.convert(this.request);
        });

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, ex.getError().getErrorCode());
    }


    // The "Basic" authentication can not be split on client ID and secret.
    @Test
    public void testConvertCanNotSplitClientId() {
        // Valid Basic authorization string contains a client ID and client secret, separated by the ":" character.
        String authorization = encodeBase64("aaa");
        this.request.addHeader(HttpHeaders.AUTHORIZATION, "Basic " + authorization);

        OAuth2AuthenticationException ex = assertThrows(OAuth2AuthenticationException.class, () -> {
            this.converter.convert(this.request);
        });

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, ex.getError().getErrorCode());
    }


    // The "Basic" authentication contains a client ID which is not a valid application/x-www-form-urlencoded.
    @Test
    public void testConvertClientIdInvalidEncoding() {
        // In a valid application/x-www-form-urlencoded string, the character "%" is an escape character which must be
        // followed by 2 hexadecimal digits.
        String authorization = encodeBase64("%zz:aaa");
        this.request.addHeader(HttpHeaders.AUTHORIZATION, "Basic " + authorization);

        OAuth2AuthenticationException ex = assertThrows(OAuth2AuthenticationException.class, () -> {
            this.converter.convert(this.request);
        });

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, ex.getError().getErrorCode());
    }


    // The "Basic" authentication contains a client secret which is not a valid application/x-www-form-urlencoded.
    @Test
    public void testConvertClientSecretInvalidEncoding() {
        // In a valid application/x-www-form-urlencoded string, the character "%" is an escape character which must be
        // followed by 2 hexadecimal digits.
        String authorization = encodeBase64("aaa:%zz");
        this.request.addHeader(HttpHeaders.AUTHORIZATION, "Basic " + authorization);

        OAuth2AuthenticationException ex = assertThrows(OAuth2AuthenticationException.class, () -> {
            this.converter.convert(this.request);
        });

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, ex.getError().getErrorCode());
    }


    // The "Basic" authentication with client ID and password which does not contain any special characters.
    @Test
    public void testConvertNoSpecialCharacters() {
        String authorization = encodeBase64("aBc:DeF");
        this.request.addHeader(HttpHeaders.AUTHORIZATION, "Basic " + authorization);

        OAuth2ClientCredentialsAuthenticationToken token =
                (OAuth2ClientCredentialsAuthenticationToken) this.converter.convert(this.request);
        assertEquals("aBc", token.getPrincipal());
        assertEquals("DeF", token.getCredentials());
    }


    // The "Basic" authentication with client ID and password which contain some special characters.
    @Test
    public void testConvertSpecialCharacters() {
        // Client ID and secret contains some exotic Unicode characters.
        String clientId = "\u1234\u5678";
        String encodedClientId = URLEncoder.encode(clientId, StandardCharsets.UTF_8);
        String clientSecret = "\uab12\ucd34";
        String encodedClientSecret = URLEncoder.encode(clientSecret, StandardCharsets.UTF_8);

        String authorization = encodeBase64(encodedClientId + ":" + encodedClientSecret);
        this.request.addHeader(HttpHeaders.AUTHORIZATION, "Basic " + authorization);

        OAuth2ClientCredentialsAuthenticationToken token =
                (OAuth2ClientCredentialsAuthenticationToken) this.converter.convert(this.request);
        assertEquals(clientId, token.getPrincipal());
        assertEquals(clientSecret, token.getCredentials());
    }
}
