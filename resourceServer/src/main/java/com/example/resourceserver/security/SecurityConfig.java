package com.example.resourceserver.security;

import com.example.resourceserver.security.JWT.JwtAuthFilter;
import com.example.resourceserver.security.JWT.JwtAuthProvider;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        List<AuthenticationProvider> providers = new ArrayList<>();
        providers.add(new JwtAuthProvider());
        return new ProviderManager(providers);
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.addAllowedOrigin("http://localhost:3000");
        configuration.addAllowedHeader("http://localhost:8081");
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
            CorsConfigurationSource corsConfigurationSource
    ) throws Exception {
        http
                .authorizeHttpRequests(authorize ->
                        authorize
                                .anyRequest().authenticated()
                )
                .csrf().disable()
                .httpBasic().disable()
                .formLogin().disable()
                .rememberMe().disable()
                .cors().configurationSource(corsConfigurationSource)
                .and()
                .addFilterAt(new JwtAuthFilter(authenticationManager), RememberMeAuthenticationFilter.class);
        return http.build();
    }
}
