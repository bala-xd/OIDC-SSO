package com.client.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.web.client.RestTemplate;

import java.util.List;

@Configuration
public class RestTemplateConfiguration {

    @Bean
    public RestTemplate restTemplate(OAuth2AuthorizedClientManager authorizedClientManager) {
        RestTemplate restTemplate = new RestTemplate();
        restTemplate.setInterceptors(List.of(oAuth2Interceptor(authorizedClientManager)));
        return restTemplate;
    }

    @Bean
    public OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientRepository authorizedClientRepository) {

        return new DefaultOAuth2AuthorizedClientManager(
                clientRegistrationRepository, authorizedClientRepository);
    }

    private ClientHttpRequestInterceptor oAuth2Interceptor(OAuth2AuthorizedClientManager authorizedClientManager) {
        return (request, body, execution) -> {
            // Get the current authentication context (the principal)
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication != null) {
                // Create an OAuth2AuthorizeRequest with the client registration ID and authentication
                OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId("custom-client")
                        .principal(authentication)
                        .build();

                // Fetch the OAuth2AuthorizedClient for the current user (Principal)
                OAuth2AuthorizedClient authorizedClient = authorizedClientManager.authorize(authorizeRequest);

                if (authorizedClient != null && authorizedClient.getAccessToken() != null) {
                    // Add the Bearer token to the Authorization header
                    request.getHeaders().setBearerAuth(authorizedClient.getAccessToken().getTokenValue());
                }
            }

            return execution.execute(request, body);
        };
    }
}
