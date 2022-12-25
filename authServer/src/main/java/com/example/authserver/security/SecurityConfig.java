package com.example.authserver.security;

import com.example.authserver.data.repository.AccountInfoRepository;
import com.example.authserver.security.logout.LogoutFilter;
import com.example.authserver.security.oauth2.code.OAuth2CodeFilter;
import com.example.authserver.security.oauth2.token.OAuth2TokenFilter;
import com.example.authserver.security.usernamePw.BasicAuthFilter;
import com.example.authserver.security.usernamePw.BasicAuthProvider;
import com.example.authserver.security.usernamePw.BasicUserDetailsService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.*;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(
            AccountInfoRepository accountInfoRepository,
            PasswordEncoder passwordEncoder
    ) {
        BasicAuthProvider basicProvider = new BasicAuthProvider(
                passwordEncoder,
                new BasicUserDetailsService(accountInfoRepository)
        );

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
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return new AuthenticationEntryPoint() {
            @Override
            public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                PrintWriter writer = response.getWriter();
                writer.println("HTTP Status 401 - " + authException.getMessage());
            }
        };
    }

    @Bean
    public SecurityFilterChain filterChain(
            HttpSecurity http,
            AuthenticationManager authenticationManager,
            CorsConfigurationSource corsConfigurationSource,
            RedisTemplate<String, Object> redisTemplate,
            AuthenticationEntryPoint authenticationEntryPoint
    ) throws Exception {
        http
                .authorizeHttpRequests(authorize ->
                        authorize
                                .requestMatchers("/jwt/refresh/", "/signup/", "/hello/").permitAll()
                                .anyRequest().authenticated()
                )
                .csrf().disable()
                .httpBasic().disable()
                .formLogin().disable()
                .rememberMe().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .cors().configurationSource(corsConfigurationSource)
                .and()
                .exceptionHandling().authenticationEntryPoint(authenticationEntryPoint)
                .and()
                .addFilterAt(new BasicAuthFilter(authenticationManager, authenticationEntryPoint), RememberMeAuthenticationFilter.class)
                .addFilterAfter(new OAuth2TokenFilter(authenticationEntryPoint), BasicAuthFilter.class)
                .addFilterAfter(new LogoutFilter(redisTemplate), OAuth2TokenFilter.class)
                .addFilterAfter(new OAuth2CodeFilter(), LogoutFilter.class);
        return http.build();
    }


}