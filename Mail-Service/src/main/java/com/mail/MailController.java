package com.mail;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;

@RestController
@CrossOrigin(origins = "http://localhost:5173")
public class MailController {

    @Autowired
    private RestTemplate restTemplate;
    
    @GetMapping("")
    public String test() {
        return "This is Mail-API";
    }

    @GetMapping("/home")
    public String hello() {
        return "Welcome, your inbox is Empty! (Client-APP 2)";
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
    public String userinfo() {
        // Access the protected resource (userinfo endpoint)
        return this.restTemplate.getForObject("http://127.0.0.1:8080/userinfo", String.class);
    }
   
}
