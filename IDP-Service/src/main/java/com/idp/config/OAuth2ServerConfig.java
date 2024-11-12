package com.idp.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Function;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.idp.service.OidcUserInfoService;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
@EnableWebSecurity
public class OAuth2ServerConfig {
	
	@Bean
    @Order(1)
    public SecurityFilterChain webFilterChainForOAuth(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        /*http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());*/
        
        Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper = (context) -> { 
			OidcUserInfoAuthenticationToken authentication = context.getAuthentication();
			JwtAuthenticationToken principal = (JwtAuthenticationToken) authentication.getPrincipal();
			System.out.println(principal.getToken());
			return new OidcUserInfo(principal.getToken().getClaims());
		};
		
		http
		.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
        .oidc((oidc) -> oidc
				.userInfoEndpoint((userInfo) -> userInfo
						.userInfoMapper(userInfoMapper) )
					);
		
        http.exceptionHandling(e -> e.authenticationEntryPoint(
                new LoginUrlAuthenticationEntryPoint("/login")
        ))
        .oauth2ResourceServer(oauth->oauth.jwt(jwt-> {
            try {
                jwt.decoder(jwtDecoder());
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }));
        return http.build();
    }
	
	@Bean
	public RegisteredClientRepository registeredClientRepository() {
	    BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
	    
	    // First client: demo-client
	    RegisteredClient demoClient = RegisteredClient.withId(UUID.randomUUID().toString())
	            .clientId("demo-client")
	            .clientSecret(encoder.encode("secret"))
	            .scope(OidcScopes.OPENID)
	            .scope(OidcScopes.PROFILE)
	            .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
	            .redirectUri("http://localhost:8085/login/oauth2/code/custom-client")
	            .postLogoutRedirectUri("http://localhost:8085")
	            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
	            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
	            .authorizationGrantTypes(
	                    grantType -> {
	                        grantType.add(AuthorizationGrantType.AUTHORIZATION_CODE);
	                        grantType.add(AuthorizationGrantType.REFRESH_TOKEN);
	                        grantType.add(AuthorizationGrantType.CLIENT_CREDENTIALS);
	                    }
	            ).build();

	    // Second client: mail-client
	    RegisteredClient mailClient = RegisteredClient.withId(UUID.randomUUID().toString())
	            .clientId("mail-client")
	            .clientSecret(encoder.encode("secret"))
	            .scope(OidcScopes.OPENID)
	            .scope(OidcScopes.PROFILE)
	            .scope(OidcScopes.EMAIL)
	            .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
	            .redirectUri("http://localhost:8090/login/oauth2/code/mail-client")
	            .postLogoutRedirectUri("http://localhost:8090")
	            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
	            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
	            .authorizationGrantTypes(
	                    grantType -> {
	                        grantType.add(AuthorizationGrantType.AUTHORIZATION_CODE);
	                        grantType.add(AuthorizationGrantType.REFRESH_TOKEN);
	                        grantType.add(AuthorizationGrantType.CLIENT_CREDENTIALS);
	                    }
	            )
	            .build();

	    // Register both clients
	    return new InMemoryRegisteredClientRepository(demoClient, mailClient);
	}

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        KeyPair keys = keyPairGenerator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keys.getPublic();
        PrivateKey privateKey = keys.getPrivate();

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder() throws NoSuchAlgorithmException {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource());
    }
    
    @Bean 
	public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(
			OidcUserInfoService userInfoService) {
		return (context) -> {
			if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
				OidcUserInfo userInfo = userInfoService.loadUser( 
						context.getPrincipal().getName());
				context.getClaims().claims(claims ->
						claims.putAll(userInfo.getClaims()));
			}
		};
	}

}
