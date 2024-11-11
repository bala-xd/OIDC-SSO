package com.client.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    protected SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorizeRequests ->
                        authorizeRequests
                                .anyRequest().authenticated() // Require authentication for all requests
                )
                .oauth2Login(oauth2Login ->
                        oauth2Login// Enable OAuth 2.0 Login
                                .defaultSuccessUrl("/hello", true) // Redirect to login page on failure
                )
                .sessionManagement(sessionManagement ->
                        sessionManagement
                                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // Create a session only when required
                                .maximumSessions(1) // Limit to one session per user
                                .maxSessionsPreventsLogin(true) // Prevents new login if already logged in
                )
                .logout(logout ->
                        logout.logoutUrl("/logout")
                                .logoutSuccessUrl("/login?logout=true") // Redirect after logout success
                )
                .oauth2Client(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable);

        return http.build(); // Build the HttpSecurity object
    }
}