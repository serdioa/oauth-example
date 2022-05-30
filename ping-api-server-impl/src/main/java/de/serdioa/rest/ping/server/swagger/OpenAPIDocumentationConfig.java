package de.serdioa.rest.ping.server.swagger;

import org.springframework.context.annotation.Bean;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Controller;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.OAuthFlow;
import io.swagger.v3.oas.annotations.security.OAuthFlows;
import io.swagger.v3.oas.annotations.security.OAuthScope;
import io.swagger.v3.oas.annotations.security.SecurityScheme;


/**
 * Home redirection to OpenAPI api documentation
 */
@Controller
@OpenAPIDefinition(info =
        @Info(title = "Ping API"))
@SecurityScheme(name = "OAuth2", type = SecuritySchemeType.OAUTH2,
        flows =
        @OAuthFlows(
                clientCredentials =
                @OAuthFlow(
                        tokenUrl = "http://localhost:8070/oauth2/token",
                        scopes = {
                            @OAuthScope(name = "read", description = "Test rest scope"),
                            @OAuthScope(name = "write", description = "Test write scope")
                        }
                )
        )
)
public class OpenAPIDocumentationConfig {

    private static final YAMLMapper yamlMapper = new YAMLMapper();

    @Value("classpath:/de/serdioa/rest/ping/api/ping.yaml")
    private Resource openapi;


    @Bean
    public String openapiContent() throws IOException {
        try ( InputStream is = openapi.getInputStream()) {
            return StreamUtils.copyToString(is, Charset.defaultCharset());
        }
    }


    @GetMapping(value = "/openapi.yaml", produces = "application/vnd.oai.openapi")
    @ResponseBody
    public String openapiYaml() throws IOException {
        return openapiContent();
    }


    @GetMapping(value = "/openapi.json", produces = "application/json")
    @ResponseBody
    public Object openapiJson() throws IOException {
        return yamlMapper.readValue(openapiContent(), Object.class);
    }


    @RequestMapping("/")
    public String index() {
        return "redirect:swagger-ui/index.html?url=../openapi.json";
    }
}
