package de.serdioa.boot.autoconfigure.webclient;

import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.JettyClientHttpConnector;
import org.springframework.http.client.reactive.JettyResourceFactory;


@Configuration
public class ClientHttpConnectorConfiguration {

    @Bean
    public JettyResourceFactory jettyClientResourceFactory() {
        return new JettyResourceFactory();
    }


    @Bean
    @ConfigurationProperties("webclient.logging")
    public LoggingHttpClientProperties jettyHttpClientConfig() {
        return new LoggingHttpClientProperties();
    }


    @Bean
    public JettyClientHttpConnector jettyClientHttpConnector(JettyResourceFactory jettyResourceFactory,
            LoggingHttpClientProperties loggingHttpClientConfig) {
        SslContextFactory sslContextFactory = new SslContextFactory.Client();

        LoggingJettyHttpClient httpClient = new LoggingJettyHttpClient(sslContextFactory);
        httpClient.setLogConfig(loggingHttpClientConfig);

        return new JettyClientHttpConnector(httpClient, jettyResourceFactory);
    }
}
