package de.serdioa.ouath.authserver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;


public class OAuth2ClientSecretPostAuthenticationConverterTest {

    private MockHttpServletRequest request;
    private OAuth2ClientSecretPostAuthenticationConverter converter;


    @BeforeEach
    public void setUp() {
        // Configuration applies to most tests.
        // Those few tests which are an exception, has to reset the header.
        this.request = new MockHttpServletRequest();
        this.request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue());

        this.converter = new OAuth2ClientSecretPostAuthenticationConverter();
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


    // There is no parameter "client_id" at all: not an error, but the converter can not extract authentication
    // information from the request, and returns null.
    @Test
    public void testConvertNoClientId() {
        assertNull(this.converter.convert(this.request));
    }


    // There is more than 1 parameter "client_id".
    @Test
    public void testConvertMultipleClientId() {
        this.request.addParameter(OAuth2ParameterNames.CLIENT_ID, "test_client_id_1");
        this.request.addParameter(OAuth2ParameterNames.CLIENT_ID, "test_client_id_2");

        OAuth2AuthenticationException ex = assertThrows(OAuth2AuthenticationException.class, () -> {
            this.converter.convert(this.request);
        });

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, ex.getError().getErrorCode());
    }


    // There is a parameter "client_id", but it is an empty string.
    @Test
    public void testConvertEmptyClientId() {
        this.request.addParameter(OAuth2ParameterNames.CLIENT_ID, "");

        OAuth2AuthenticationException ex = assertThrows(OAuth2AuthenticationException.class, () -> {
            this.converter.convert(this.request);
        });

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, ex.getError().getErrorCode());
    }


    // There is a parameter "client_id", but it contains only whitespace characters.
    @Test
    public void testConvertWhitespaceClientId() {
        this.request.addParameter(OAuth2ParameterNames.CLIENT_ID, "   ");

        OAuth2AuthenticationException ex = assertThrows(OAuth2AuthenticationException.class, () -> {
            this.converter.convert(this.request);
        });

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, ex.getError().getErrorCode());
    }


    // There is no parameter "client_secret".
    // According to RFC 6749, section 2.3, the client_secret may be omitted if it is an empty string.
    @Test
    public void testConvertNoClientSecret() {
        this.request.addParameter(OAuth2ParameterNames.CLIENT_ID, "test_client_id");

        OAuth2ClientCredentialsAuthenticationToken token =
                (OAuth2ClientCredentialsAuthenticationToken) this.converter.convert(this.request);
        assertEquals("test_client_id", token.getPrincipal());
        assertEquals("", token.getCredentials());
    }


    // There is more than 1 parameter "client_secret".
    @Test
    public void testConvertMultipleClientSecret() {
        this.request.addParameter(OAuth2ParameterNames.CLIENT_ID, "test_client_id");
        this.request.addParameter(OAuth2ParameterNames.CLIENT_SECRET, "test_client_secret_1");
        this.request.addParameter(OAuth2ParameterNames.CLIENT_SECRET, "test_client_secret_2");

        OAuth2AuthenticationException ex = assertThrows(OAuth2AuthenticationException.class, () -> {
            this.converter.convert(this.request);
        });

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, ex.getError().getErrorCode());
    }


    // The parameter-based authentication with client ID and password which does not contain any special characters.
    @Test
    public void testConvertNoSpecialCharacters() {
        this.request.addParameter(OAuth2ParameterNames.CLIENT_ID, "aBc");
        this.request.addParameter(OAuth2ParameterNames.CLIENT_SECRET, "DeF");

        OAuth2ClientCredentialsAuthenticationToken token =
                (OAuth2ClientCredentialsAuthenticationToken) this.converter.convert(this.request);
        assertEquals("aBc", token.getPrincipal());
        assertEquals("DeF", token.getCredentials());
    }


    // The parameter-based authentication with client ID and password which contain some special characters.
    @Test
    public void testConvertSpecialCharacters() {
        String clientId = "\u1234\u5678";
        String clientSecret = "\uab12\ucd34";
        this.request.addParameter(OAuth2ParameterNames.CLIENT_ID, clientId);
        this.request.addParameter(OAuth2ParameterNames.CLIENT_SECRET, clientSecret);

        OAuth2ClientCredentialsAuthenticationToken token =
                (OAuth2ClientCredentialsAuthenticationToken) this.converter.convert(this.request);
        assertEquals(clientId, token.getPrincipal());
        assertEquals(clientSecret, token.getCredentials());
    }
}
