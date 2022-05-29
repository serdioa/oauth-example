package de.serdioa.ouath.authserver;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Random;

import lombok.Setter;
import org.slf4j.Logger;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;


public class OAuth2ExceptionHelper {

    private static final DateTimeFormatter TIMESTAMP_FORMAT =
            DateTimeFormatter.ofPattern("yyyyMMddHHmmss");
    private static final ZoneId UTC = ZoneId.of("UTC");

    private static final String OAUTH2_ERROR_DESCRIPTION_URI =
            "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    @Setter
    private Random rnd = new SecureRandom();

    @Setter
    private int numBits = 128;


    public String nextExceptionId() {
        return TIMESTAMP_FORMAT.format(OffsetDateTime.now(UTC)) + "-"
                + new BigInteger(this.numBits, this.rnd).toString(Character.MAX_RADIX);
    }


    public OAuth2Error error(String errorCode) {
        String id = nextExceptionId();
        return this.error(errorCode, id, null);
    }


    public OAuth2Error error(String errorCode, String id, String description) {
        String message;
        if (id != null && description != null) {
            message = id + " - " + description;
        } else if (id != null) {
            message = id;
        } else {
            message = description;
        }

        return new OAuth2Error(errorCode, message, OAUTH2_ERROR_DESCRIPTION_URI);
    }


    public OAuth2AuthenticationException authenticationException(String errorCode) {
        String id = nextExceptionId();
        return this.authenticationException(errorCode, id, null);
    }


    public OAuth2AuthenticationException authenticationException(String errorCode, String id, String description) {
        OAuth2Error error = this.error(errorCode, id, description);
        return new OAuth2AuthenticationException(error);
    }


    public OAuth2AuthenticationException authenticationException(Logger logger, String errorCode, String description) {
        String id = this.nextExceptionId();
        logger.info("{}: {}", id, description);
        return this.authenticationException(errorCode, id, description);
    }
}
