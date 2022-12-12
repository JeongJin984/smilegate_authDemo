package com.example.authserver.security;

import com.example.authserver.data.repository.AccountInfoRepository;
import com.example.authserver.security.JWT.JwtAuthFilter;
import com.example.authserver.security.JWT.JwtAuthProvider;
import com.example.authserver.security.usernamePw.BasicAuthFilter;
import com.example.authserver.security.usernamePw.BasicAuthProvider;
import com.example.authserver.security.usernamePw.BasicUserDetailsService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
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

        JwtAuthProvider jwtProvider = new JwtAuthProvider();

        List<AuthenticationProvider> providers = new ArrayList<>();
        providers.add(basicProvider);
        providers.add(jwtProvider);
        return new ProviderManager(providers);
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.addAllowedOrigin("http://localhost:3000");
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
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated()
                )
                .csrf().disable()
                .httpBasic().disable()
                .formLogin().disable()
                .rememberMe().disable()
                .cors().configurationSource(corsConfigurationSource)
                .and()
                .exceptionHandling().authenticationEntryPoint(new AuthenticationEntryPoint() {
                    @Override
                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {

                    }
                })
                .and()
                .addFilterAt(new BasicAuthFilter(authenticationManager), RememberMeAuthenticationFilter.class)
                .addFilterBefore(new JwtAuthFilter(authenticationManager), BasicAuthFilter.class);
        return http.build();
    }
}
