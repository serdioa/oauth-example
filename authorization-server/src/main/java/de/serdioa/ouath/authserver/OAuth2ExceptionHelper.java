package de.serdioa.ouath.authserver;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Random;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;


public class OAuth2ExceptionHelper {

    private static final DateTimeFormatter TIMESTAMP_FORMAT =
            DateTimeFormatter.ofPattern("yyyyMMddHHmmss");
    private static final ZoneId UTC = ZoneId.of("UTC");

    private static final String OAUTH2_ERROR_DESCRIPTION_URI =
            "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    private Random rnd = new SecureRandom();
    private int numBits = 128;


    public String nextExceptionId() {
        return TIMESTAMP_FORMAT.format(OffsetDateTime.now(UTC)) + "-"
                + new BigInteger(this.numBits, this.rnd).toString(Character.MAX_RADIX);
    }


    public OAuth2Error error(String errorCode) {
        String id = nextExceptionId();
        return this.error(errorCode, id);
    }


    public OAuth2Error error(String errorCode, String id) {
        return new OAuth2Error(errorCode, id, OAUTH2_ERROR_DESCRIPTION_URI);
    }


    public OAuth2AuthenticationException authenticationException(String errorCode) {
        String id = nextExceptionId();
        return this.authenticationException(errorCode, id);
    }


    public OAuth2AuthenticationException authenticationException(String errorCode, String id) {
        OAuth2Error error = this.error(errorCode, id);
        return new OAuth2AuthenticationException(error);
    }
}
