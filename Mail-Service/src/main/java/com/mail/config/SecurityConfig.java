package com.mail.config;

import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.CorsBeanDefinitionParser;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
	
	@Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedOriginPattern("*"); // Allow all origins (adjust as necessary)
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type")); // Adjust headers as needed
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        
        return source;
    }

    @Bean
    protected SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorizeRequests ->
                        authorizeRequests
                                .anyRequest().authenticated() // Require authentication for all requests
                )
                .oauth2Login(oauth2Login ->
                        oauth2Login// Enable OAuth 2.0 Login
                                .defaultSuccessUrl("/home", true) // Redirect to login page on failure
                )
                .sessionManagement(sessionManagement ->
                        sessionManagement
                                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // Create a session only when required
                                .maximumSessions(1) // Limit to one session per user
                                .maxSessionsPreventsLogin(true) // Prevents new login if already logged in
                )
                .logout(logout ->
                        logout
                        .logoutSuccessHandler((request, response, authentication) -> {
                            // Clear client-side session
                            request.getSession().invalidate();
                            
                            // Redirect to authorization server logout endpoint
                            response.sendRedirect("http://127.0.0.1:8080/logout");
                        })
                        .clearAuthentication(true)
                        .invalidateHttpSession(true)
                )
                .oauth2Client(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults())
                .cors(cors->cors.configurationSource(corsConfigurationSource()))
                .csrf(AbstractHttpConfigurer::disable);

        return http.build(); // Build the HttpSecurity object
    }
}