package com.client;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.util.Map;
import java.util.Optional;

@RestController
public class HomeController {

    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;

    @Autowired
    private RestTemplate restTemplate;

    @GetMapping("/hello")
    public String hello() {
        return "helooooo";
    }

    @GetMapping("/tokens")
    public ResponseEntity<?> displayTokens(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient, @AuthenticationPrincipal OidcUser user, OAuth2AuthenticationToken authentication) {

        // Get ID Token Claims as a Map
        Map<String, Object> idTokenClaims = user.getIdToken().getClaims();

        // Get Access Token details
        Map<String, Object> accessTokenDetails = Map.of(
                "Granted Authorities", authentication.getAuthorities(),
                "User Attributes", authentication.getPrincipal().getAttributes()
        );

        /*Map<String, Object> response = Map.of(
                "Access Token", authorizedClient.getAccessToken().getTokenValue(),
                "ID Token", user.getIdToken().getTokenValue()
        );*/

        Map<String, Object> response = Map.of(
                "Access Token", accessTokenDetails,
                "ID Token", idTokenClaims
        );

        return ResponseEntity.ok(response);
    }

    @GetMapping("/user")
    public String users() {
        // Access the protected resource (userinfo endpoint)
        return this.restTemplate.getForObject("http://127.0.0.1:8080/userinfo", String.class);
    }
}
