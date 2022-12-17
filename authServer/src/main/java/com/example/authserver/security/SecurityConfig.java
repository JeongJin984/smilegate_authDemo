package com.example.authserver.security;

import com.example.authserver.data.repository.AccountInfoRepository;
import com.example.authserver.security.oauth2.code.OAuth2CodeFilter;
import com.example.authserver.security.usernamePw.BasicAuthFilter;
import com.example.authserver.security.usernamePw.BasicAuthProvider;
import com.example.authserver.security.usernamePw.BasicUserDetailsService;
import jakarta.persistence.Basic;
import jakarta.servlet.Filter;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationCodeGrantFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.io.IOException;
import java.util.*;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public AuthenticationManager authenticationManager(
            AccountInfoRepository accountInfoRepository
    ) throws Exception {
        BasicAuthProvider basicProvider = new BasicAuthProvider();
        basicProvider.setPasswordEncoder(new PasswordEncoder() {
            @Override
            public String encode(CharSequence rawPassword) {
                return rawPassword.toString();
            }

            @Override
            public boolean matches(CharSequence rawPassword, String encodedPassword) {
                return rawPassword.toString().equals(encodedPassword);
            }
        });
        basicProvider.setUserDetailsService(new BasicUserDetailsService(accountInfoRepository));

        List<AuthenticationProvider> providers = new ArrayList<>();
        providers.add(basicProvider);
        return new ProviderManager(providers);
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.addAllowedOrigin("http://localhost:3000");
        configuration.addAllowedOrigin("http://localhost:8082");
        configuration.addAllowedHeader("*");
        configuration.addAllowedMethod("*");
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public SecurityFilterChain filterChain(
            HttpSecurity http,
            AuthenticationManager authenticationManager,
            CorsConfigurationSource corsConfigurationSource,
            DefaultOAuth2AuthorizedClientManager oAuth2AuthorizedClientManager
    ) throws Exception {
        http
                .authorizeHttpRequests(authorize ->
                        authorize
                                .requestMatchers("/jwt/valid/").permitAll()
                                .anyRequest().authenticated()
                )
                .csrf().disable()
                .httpBasic().disable()
                .formLogin().disable()
                .rememberMe().disable()
                .cors().configurationSource(corsConfigurationSource)
                .and()
                .addFilterAt(new BasicAuthFilter(authenticationManager), RememberMeAuthenticationFilter.class)
                .addFilterAfter(new OAuth2CodeFilter(authenticationManager), BasicAuthFilter.class);
        return http.build();
    }
}