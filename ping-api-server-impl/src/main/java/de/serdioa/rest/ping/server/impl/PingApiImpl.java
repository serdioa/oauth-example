package de.serdioa.rest.ping.server.impl;

import java.time.OffsetDateTime;
import java.util.Optional;

import de.serdioa.rest.ping.api.PingApiDelegate;
import de.serdioa.rest.ping.model.Ping;
import de.serdioa.rest.ping.model.Pong;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.NativeWebRequest;


@Service
public class PingApiImpl implements PingApiDelegate {

    private static final String DEFAULT_TOKEN = "token";

    private final NativeWebRequest request;


    public PingApiImpl(NativeWebRequest request) {
        this.request = request;
    }


    @Override
    public Optional<NativeWebRequest> getRequest() {
        return Optional.ofNullable(this.request);
    }


    @Override
    @PreAuthorize("hasAuthority('read')")
    public ResponseEntity<Pong> restV1PingGet() {
        SecurityTestHelper.printAuthDetails();

        Pong pong = new Pong();
        pong.setTimestamp(OffsetDateTime.now());
        pong.setToken(DEFAULT_TOKEN);

        return ResponseEntity.ok(pong);
    }


    @Override
    @PreAuthorize("hasAuthority('write')")
    public ResponseEntity<Pong> restV1PingPost(String token) {
        SecurityTestHelper.printAuthDetails();

        Pong pong = new Pong();
        pong.setTimestamp(OffsetDateTime.now());
        pong.setToken(token != null ? token : DEFAULT_TOKEN);

        if (token.equals("error")) {
            return ResponseEntity.badRequest().body(pong);
        } else {
            return ResponseEntity.ok(pong);
        }
    }


    @Override
    @PreAuthorize("hasAuthority('write')")
    public ResponseEntity<Pong> restV1PingbodyPost(Ping ping) {
        SecurityTestHelper.printAuthDetails();

        String token = ping.getToken();

        Pong pong = new Pong();
        pong.setTimestamp(OffsetDateTime.now());
        pong.setToken(token != null ? token : DEFAULT_TOKEN);

        if (token.startsWith("error")) {
            return ResponseEntity.badRequest().body(pong);
        } else {
            return ResponseEntity.ok(pong);
        }
    }
}
