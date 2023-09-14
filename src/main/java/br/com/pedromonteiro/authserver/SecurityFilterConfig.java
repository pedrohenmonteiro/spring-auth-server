package br.com.pedromonteiro.authserver;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

@Configuration
public class SecurityFilterConfig {
    
 @Bean
 SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

     http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(
             withDefaults()
     ).and()
     .exceptionHandling((exceptions) -> exceptions.authenticationEntryPoint(
        new LoginUrlAuthenticationEntryPoint("/login"))).oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

        return http.build();
 }
}
