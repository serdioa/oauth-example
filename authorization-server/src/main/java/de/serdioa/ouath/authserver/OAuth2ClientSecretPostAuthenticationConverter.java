package de.serdioa.ouath.authserver;

import javax.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.StringUtils;


/**
 * Attempts to extract OAuth2 Client Secret request token from a request assuming authorization in the POST request
 * body.
 */
public class OAuth2ClientSecretPostAuthenticationConverter extends OAuth2ClientSecretAbstractAuthenticationConverter {

    @Override
    protected ClientAuthenticationMethod getClientAuthenticationMethod() {
        return ClientAuthenticationMethod.CLIENT_SECRET_POST;
    }


    @Override
    protected Authentication convertClientPrincipal(HttpServletRequest request) {
        String[] clientIdParameters = request.getParameterValues(OAuth2ParameterNames.CLIENT_ID);
        if (clientIdParameters == null) {
            // This request does not contain OAuth2 Client Secret authorization parameters at all.
            return null;
        }
        if (clientIdParameters.length != 1) {
            throw this.invalidRequest("More than 1 request parameter 'client_id'");
        }

        String clientId = clientIdParameters[0];
        if (!StringUtils.hasText(clientId)) {
            throw this
                    .invalidRequest("Value of the request parameter 'client_id' is not available or is an empty string");
        }

        String[] clientSecretParameters = request.getParameterValues(OAuth2ParameterNames.CLIENT_SECRET);
        String clientSecret;
        if (clientSecretParameters == null) {
            // RFC 6749, section 2.3: The client MAY omit the parameter if the client secret is an empty string.
            clientSecret = "";
        } else if (clientSecretParameters.length != 1) {
            throw this.invalidRequest("More than 1 request parameter 'client_secret'");
        } else {
            clientSecret = clientSecretParameters[0];
        }

        return new UsernamePasswordAuthenticationToken(clientId, clientSecret);
    }
}
