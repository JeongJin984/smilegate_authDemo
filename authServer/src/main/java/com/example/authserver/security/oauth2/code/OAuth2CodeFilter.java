package com.example.authserver.security.oauth2.code;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Base64;
import java.util.Random;

public class OAuth2CodeFilter extends OncePerRequestFilter {

    private final RequestMatcher requiresAuthenticationRequestMatcher;
    private final RedisTemplate<String, Object> redisTemplate;

    public OAuth2CodeFilter(RedisTemplate<String, Object> redisTemplate) {
        this.requiresAuthenticationRequestMatcher = new AntPathRequestMatcher("/login/oauth2/keycloack/*");
        this.redisTemplate = redisTemplate;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        if(requiresAuthenticationRequestMatcher.matches(request)) {
            byte[] stateArray = new byte[32];
            new Random().nextBytes(stateArray);
            String state = Base64.getEncoder().encodeToString(stateArray);

            byte[] nonceArray = new byte[32];
            new Random().nextBytes(nonceArray);
            String nonce = Base64.getEncoder().encodeToString(nonceArray);

            redisTemplate.opsForValue().set(state, "csrf");

            response.sendRedirect(
                    "http://localhost:8080/realms/oauth2/protocol/openid-connect/auth?" +
                            "response_type=code&client_id=oauth-client-app&scope=openid%20email&state=" + state +
                            "&redirect_uri=http://localhost:8081/login/oauth2/code/keycloack&nonce=" + nonce);
        }
    }

}
