package de.serdioa.rest.ping.server.impl;

import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.Optional;

import de.serdioa.rest.ping.api.PingApiDelegate;
import de.serdioa.rest.ping.model.Pong;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
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
    public ResponseEntity<Pong> restV1PingGet() {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        System.out
                .printf("securityContext=%s (%s)%n", securityContext, (securityContext == null ? null : securityContext
                        .getClass()));

        if (securityContext != null) {
            Authentication authentication = securityContext.getAuthentication();
            System.out
                    .printf("authentication=%s (%s)%n", authentication, (authentication == null ? null : authentication
                            .getClass()));

            if (authentication != null) {
                String name = authentication.getName();
                System.out.printf("name=%s (%s)%n", name, (name == null ? null : name.getClass()));

                Object principal = authentication.getPrincipal();
                System.out.printf("principal=%s (%s)%n", principal, (principal == null ? null : principal.getClass()));

                if (principal instanceof UserDetails) {
                    String principalName = ((UserDetails) principal).getUsername();
                    System.out
                            .printf("principalName=%s (%s)%n", principalName, (principalName == null ? null : principalName
                                    .getClass()));
                }

                Object details = authentication.getDetails();
                System.out.printf("details=%s (%s)%n", details, (details == null ? null : details.getClass()));

                Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
                System.out.printf("authorities=%s (%s)%n", authorities, (authorities == null ? null : authorities
                        .getClass()));
            }
        }

        Pong pong = new Pong();
        pong.setTimestamp(OffsetDateTime.now());
        pong.setToken(DEFAULT_TOKEN);

        return ResponseEntity.ok(pong);
    }


    @Override
    public ResponseEntity<Pong> restV1PingPost(String token) {
        Pong pong = new Pong();
        pong.setTimestamp(OffsetDateTime.now());
        pong.setToken(token != null ? token : DEFAULT_TOKEN);

        return ResponseEntity.ok(pong);
    }
}
