package com.idp.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class AuthController {

    @GetMapping("")
    public String test() {
        return "This is Auth-API";
    }

    /*@GetMapping("/userinfo")
    public String getUserInfo(@AuthenticationPrincipal OAuth2User principal) {

        return principal+" ";
    }*/

    /*@GetMapping("/userinfo")
    public ResponseEntity<?> getUserInfo(@AuthenticationPrincipal OAuth2User principal) {

        return ResponseEntity.ok()
                .header("Content-Type", "application/json")
                .body(principal);
    }*/

}
