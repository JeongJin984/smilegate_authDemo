package com.example.authserver.security.logout;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;

public class LogoutFilter extends OncePerRequestFilter {

    private final RedisTemplate<String, Object> redisTemplate;
    private final RequestMatcher requiresAuthenticationRequestMatcher = new AntPathRequestMatcher("/logout/*");

    public LogoutFilter(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(requiresAuthenticationRequestMatcher.matches(request)) {
            String platform = "";
            String accessToken = "";
            String refreshToken = "";
            String loginUser = "";
            Instant expireAt = null;

            for(Cookie cookie : request.getCookies()) {
                if(cookie.getName().equals("platform")) {
                    platform = cookie.getValue();
                } else if(cookie.getName().equals("accessToken")) {
                    accessToken = cookie.getValue();
                } else if(cookie.getName().equals("refreshToken")) {
                    refreshToken = cookie.getValue();
                } else if(cookie.getName().equals("user")) {
                    loginUser = cookie.getName();
                } else if(cookie.getName().equals("expireAt")) {
                    expireAt = Instant.parse(cookie.getValue());
                }
            }

            assert StringUtils.hasText(platform);
            assert StringUtils.hasText(accessToken);
            assert StringUtils.hasText(refreshToken);
            assert expireAt != null;

            Cookie accessTokenCookie = new Cookie("accessToken", null);
            accessTokenCookie.setPath("/");
            accessTokenCookie.setSecure(false);
            accessTokenCookie.setHttpOnly(true);
            accessTokenCookie.setMaxAge(0);
            response.addCookie(accessTokenCookie);

            Cookie refreshTokenCookie = new Cookie("refreshToken", null);
            refreshTokenCookie.setPath("/");
            refreshTokenCookie.setSecure(false);
            refreshTokenCookie.setHttpOnly(true);
            refreshTokenCookie.setMaxAge(0);
            response.addCookie(refreshTokenCookie);

            Cookie platformCookie = new Cookie("platform", null);
            platformCookie.setPath("/");
            platformCookie.setSecure(false);
            platformCookie.setHttpOnly(true);
            platformCookie.setMaxAge(0);
            response.addCookie(platformCookie);

            Cookie userCookie = new Cookie("user", null);
            userCookie.setPath("/");
            userCookie.setSecure(false);
            userCookie.setHttpOnly(true);
            userCookie.setMaxAge(0);
            response.addCookie(userCookie);

            Cookie expireAtCookie = new Cookie("expireAt", null);
            expireAtCookie.setPath("/");
            expireAtCookie.setSecure(false);
            expireAtCookie.setHttpOnly(true);
            expireAtCookie.setMaxAge(0);
            response.addCookie(expireAtCookie);

            Cookie idTokenCookie = new Cookie("idToken", null);
            idTokenCookie.setPath("/");
            idTokenCookie.setSecure(false);
            idTokenCookie.setHttpOnly(true);
            idTokenCookie.setMaxAge(0);
            response.addCookie(idTokenCookie);

            redisTemplate.opsForSet().add(refreshToken, "expired");
            redisTemplate.expireAt(refreshToken, expireAt);
        } else {
            filterChain.doFilter(request, response);
        }
    }
}
