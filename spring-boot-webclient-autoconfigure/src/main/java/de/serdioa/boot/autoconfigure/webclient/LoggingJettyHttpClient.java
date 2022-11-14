package de.serdioa.boot.autoconfigure.webclient;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicLong;

import lombok.Setter;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.HttpClientTransport;
import org.eclipse.jetty.client.api.Request;
import org.eclipse.jetty.http.HttpField;
import org.eclipse.jetty.http.HttpFields;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class LoggingJettyHttpClient extends HttpClient {

    private static final Logger logger = LoggerFactory.getLogger(LoggingJettyHttpClient.class);

    @Setter
    private LoggingHttpClientProperties logConfig = new LoggingHttpClientProperties();

    private final AtomicLong requesCounter = new AtomicLong();


    public LoggingJettyHttpClient() {
        super();
    }


    public LoggingJettyHttpClient(SslContextFactory sslContextFactory) {
        super(sslContextFactory);
    }


    public LoggingJettyHttpClient(HttpClientTransport transport) {
        super(transport);
    }


    public LoggingJettyHttpClient(HttpClientTransport transport, SslContextFactory sslContextFactory) {
        super(transport, sslContextFactory);
    }


    @Override
    public Request newRequest(URI uri) {
        final Request request = super.newRequest(uri);

        if (this.logConfig.isEnabled()) {
            this.addLogging(request);
        }

        return request;
    }


    private void addLogging(Request request) {
        final long count = this.requesCounter.incrementAndGet();
        final String method = request.getMethod();
        final URI uri = request.getURI();

        if (this.logConfig.getRequest().isEnabled()) {
            final StringBuilder logRequest = new StringBuilder();
            logRequest.append(this.logConfig.getName()).append(" #").append(count)
                    .append(" ").append(method).append(" ").append(uri);

            if (this.logConfig.getRequest().getHeaders().isEnabled()) {
                this.logHeaders(request.getHeaders(), this.logConfig.getRequest().getHeaders(), logRequest);
            }

            if (this.logConfig.getRequest().getBody().isEnabled()) {
                request.onRequestContent((req, content) -> {
                    String bufferAsString = StandardCharsets.UTF_8.decode(content).toString();
                    logRequest.append(", Body: ").append(bufferAsString);
                });
            }

            // Add actual log invocation
            request.onRequestSuccess(req -> {
                logger.info("Request sent: {}", logRequest);
            });
            request.onRequestFailure((req, ex) -> {
                logger.warn("Request failed: {}", logRequest, ex);
            });
        }

        if (this.logConfig.getResponse().isEnabled()) {
            final StringBuilder logResponse = new StringBuilder();
            logResponse.append(this.logConfig.getName()).append(" #").append(count)
                    .append(" ").append(method).append(" ").append(uri);

            request.onResponseBegin(resp -> {
                logResponse.append(" returned HTTP ").append(resp.getStatus());
            });

            if (this.logConfig.getResponse().getHeaders().isEnabled()) {
                request.onResponseHeaders(resp -> {
                    this.logHeaders(resp.getHeaders(), this.logConfig.getResponse().getHeaders(), logResponse);
                });
            }

            if (this.logConfig.getResponse().getBody().isEnabled()) {
                request.onResponseContent((resp, content) -> {
                    String bufferAsString = StandardCharsets.UTF_8.decode(content).toString();
                    logResponse.append(", Body: ").append(bufferAsString);
                });
            }

            // Add actual log invocation
            request.onResponseSuccess(resp -> {
                logger.info("Response received: {}", logResponse);
            });
            request.onRequestFailure((req, ex) -> {
                logger.warn("Receiving response failed: {}", logResponse, ex);
            });
        }
    }


    private void logHeaders(HttpFields headers, LoggingHttpClientProperties.DetailHeadersLogProperties headersLogProperties,
            StringBuilder target) {
        target.append(", Headers: [");

        boolean headerLogged = false;
        for (HttpField header : headers) {
            final String name = header.getName();
            if (headersLogProperties.isLogHeader(name)) {
                for (String value : header.getValues()) {
                    if (headerLogged) {
                        target.append(", ");
                    }
                    target.append(name).append(": ").append(value);
                    headerLogged = true;
                }
            }
        }

        target.append("]");
    }
}
