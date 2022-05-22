package de.serdioa.ouath.authserver;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

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
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;


@Component
@WebFilter("/oauth2/token")
public class OAuthTokenEndpointFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(OAuthTokenEndpointFilter.class);

    private final HttpMessageConverter<OAuth2AccessTokenResponse> tokenResponseConverter =
            new OAuth2AccessTokenResponseHttpMessageConverter();
    private final HttpMessageConverter<OAuth2Error> errorResponseConverter =
            new OAuth2ErrorHttpMessageConverter();

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private OAuth2ExceptionHelper exceptionHelper;

    private AuthenticationSuccessHandler authenticationSuccessHandler = this::sendAccessTokenResponse;
    private AuthenticationFailureHandler authenticationFailureHandler = this::sendErrorResponse;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        OAuth2ClientCredentialsAuthenticationToken authenticationToken =
                new OAuth2ClientCredentialsAuthenticationToken("my-client-id", "my-client-secret",
                        ClientAuthenticationMethod.CLIENT_SECRET_BASIC, Set.of("aaa", "bbb", "ccc"),
                        Collections.emptyMap());
        OAuth2AccessTokenAuthenticationToken accessToken =
                (OAuth2AccessTokenAuthenticationToken) this.authenticationManager.authenticate(authenticationToken);

        logger.debug("accessToken=" + accessToken);

        if (accessToken != null) {
            this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, accessToken);
        } else {
            OAuth2AuthenticationException ex = this.exceptionHelper
                    .authenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
            this.authenticationFailureHandler.onAuthenticationFailure(request, response, ex);
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
