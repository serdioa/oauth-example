package de.serdioa.ouath.authserver;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;


@Component
@WebFilter("/oauth2/token")
public class OAuthTokenEndpointFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(OAuthTokenEndpointFilter.class);

    private final HttpMessageConverter<OAuth2AccessTokenResponse> tokenResponseConverter =
            new OAuth2AccessTokenResponseHttpMessageConverter();
    private final HttpMessageConverter<OAuth2Error> errorResponseConverter =
            new OAuth2ErrorHttpMessageConverter();

    private AuthenticationConverter authenticationConverter;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private OAuth2ExceptionHelper exceptionHelper;

    private AuthenticationSuccessHandler authenticationSuccessHandler = this::sendAccessTokenResponse;
    private AuthenticationFailureHandler authenticationFailureHandler = this::sendErrorResponse;


    @PostConstruct
    @Override
    public void afterPropertiesSet() throws ServletException {
        super.afterPropertiesSet();

        AuthenticationConverter basicAuthenticationConverter = new OAuth2ClientSecretBasicAuthenticationConverter();
        AuthenticationConverter postAuthenticationConverter = new OAuth2ClientSecretPostAuthenticationConverter();
        this.authenticationConverter = new OAuth2ClientSecretDelegatingAuthenticationConverter(
                Arrays.asList(basicAuthenticationConverter, postAuthenticationConverter), true);
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            this.validateGrantType(request);

            OAuth2ClientCredentialsAuthenticationToken authenticationToken =
                    (OAuth2ClientCredentialsAuthenticationToken) this.authenticationConverter.convert(request);

            if (authenticationToken == null) {
                throw this.exceptionHelper.authenticationException(logger, OAuth2ErrorCodes.INVALID_REQUEST,
                        "HTTP request does not contain authorization header or parameters");
            }

            OAuth2AccessTokenAuthenticationToken accessToken =
                    (OAuth2AccessTokenAuthenticationToken) this.authenticationManager.authenticate(authenticationToken);

            logger.debug("accessToken=" + accessToken);

            this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, accessToken);
        } catch (OAuth2AuthenticationException ex) {
            this.authenticationFailureHandler.onAuthenticationFailure(request, response, ex);
        }

    }


    private void validateGrantType(HttpServletRequest request) {
        String[] grantTypeValues = request.getParameterValues(OAuth2ParameterNames.GRANT_TYPE);
        if (grantTypeValues == null) {
            throw this.exceptionHelper.authenticationException(logger, OAuth2ErrorCodes.INVALID_REQUEST,
                    "Request parameter 'grant_type' is not available");
        }
        if (grantTypeValues.length != 1) {
            throw this.exceptionHelper.authenticationException(logger, OAuth2ErrorCodes.INVALID_REQUEST,
                    "More than 1 request parameter 'grant_type'");
        }
        String grantType = grantTypeValues[0];
        if (!StringUtils.hasText(grantType)) {
            throw this.exceptionHelper.authenticationException(logger, OAuth2ErrorCodes.INVALID_REQUEST,
                    "Value of the request parameter 'grant_type' is not available or is an empty string");
        }

        if (!AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(grantType)) {
            // This request is not for a client credentials.
            throw this.exceptionHelper.authenticationException(logger, OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE,
                    "Unsupported 'grant_type': " + grantType);
        }
    }


    private void sendAccessTokenResponse(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException {
        OAuth2AccessTokenAuthenticationToken accessTokenAuthentication =
                (OAuth2AccessTokenAuthenticationToken) authentication;
        OAuth2AccessToken accessToken = accessTokenAuthentication.getAccessToken();
        Map<String, Object> additionalParameters = accessTokenAuthentication.getAdditionalParameters();

        OAuth2AccessTokenResponse.Builder responseBuilder = OAuth2AccessTokenResponse
                .withToken(accessToken.getTokenValue())
                .tokenType(accessToken.getTokenType())
                .scopes(accessToken.getScopes());

        Instant issuedAt = accessToken.getIssuedAt();
        Instant expiresAt = accessToken.getExpiresAt();
        if (issuedAt != null && expiresAt != null) {
            long expiresInSeconds = ChronoUnit.SECONDS.between(issuedAt, expiresAt);
            responseBuilder.expiresIn(expiresInSeconds);
        }

        if (additionalParameters != null && !additionalParameters.isEmpty()) {
            responseBuilder.additionalParameters(additionalParameters);
        }

        OAuth2AccessTokenResponse accessTokenResponse = responseBuilder.build();
        ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
        this.tokenResponseConverter.write(accessTokenResponse, MediaType.APPLICATION_JSON, httpResponse);
    }


    private void sendErrorResponse(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException exception) throws IOException {
        OAuth2AuthenticationException oauth2Exception = (OAuth2AuthenticationException) exception;
        OAuth2Error oauth2Error = oauth2Exception.getError();

        ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
        httpResponse.setStatusCode(HttpStatus.BAD_REQUEST);
        this.errorResponseConverter.write(oauth2Error, MediaType.APPLICATION_JSON, httpResponse);
    }
}
