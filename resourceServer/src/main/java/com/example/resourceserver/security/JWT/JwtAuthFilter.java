package com.example.resourceserver.security.JWT;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.core.log.LogMessage;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;

import static java.lang.Long.parseLong;

public class JwtAuthFilter extends OncePerRequestFilter implements ApplicationEventPublisherAware {
    private final SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
            .getContextHolderStrategy();

    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

    private final JwtAuthConverter jwtAuthConverter = new JwtAuthConverter();
    private final OAuth2TokenConverter oAuth2TokenConverter = new OAuth2TokenConverter();

    private ApplicationEventPublisher eventPublisher;

    private AuthenticationSuccessHandler successHandler;

    private final AuthenticationManager authenticationManager;

    private final RestTemplate restTemplate = new RestTemplate();

    public JwtAuthFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        String loginPlatform = null;
        Instant keycloackTokenExpireAt = null;
        String refreshToken = null;
        for(Cookie cookie : request.getCookies()) {
            if(cookie.getName().equals("platform")) {
                loginPlatform = cookie.getValue();
            } else if(cookie.getName().equals("expireAt")) {
                keycloackTokenExpireAt = Instant.parse(cookie.getValue());
            } else if(cookie.getName().equals("refreshToken")) {
                refreshToken = cookie.getValue();
            }
        }

        assert keycloackTokenExpireAt != null;
        assert loginPlatform != null;
        assert refreshToken != null;

        if(loginPlatform.equals("JWT")) {
            Authentication jwtAuthToken = jwtAuthConverter.convert(request);
            try {
                if (jwtAuthToken == null) {
                    chain.doFilter(request, response);
                    return;
                }

                jwtAuthToken = authenticationManager.authenticate(jwtAuthToken);
                SecurityContext context = this.securityContextHolderStrategy.createEmptyContext();
                context.setAuthentication(jwtAuthToken);
                this.securityContextHolderStrategy.setContext(context);
                onSuccessfulAuthentication(request, response, jwtAuthToken);

                this.logger.debug(LogMessage.of(() -> "SecurityContextHolder populated with remember-me token: '"
                        + this.securityContextHolderStrategy.getContext().getAuthentication() + "'"));
                this.securityContextRepository.saveContext(context, request, response);

                if (this.eventPublisher != null) {
                    this.eventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(
                            this.securityContextHolderStrategy.getContext().getAuthentication(), this.getClass()));
                }
                if (this.successHandler != null) {
                    this.successHandler.onAuthenticationSuccess(request, response, jwtAuthToken);
                }
            } catch (AuthenticationException ex) {
                this.logger.debug("Interactive login attempt was unsuccessful.");
                onLoginFail(request, response);
            }
        } else if(loginPlatform.equals("keycloack")) {
            try {
                Authentication oAuth2AuthToken = oAuth2TokenConverter.convert(request);
                SecurityContext context = this.securityContextHolderStrategy.createEmptyContext();
                context.setAuthentication(oAuth2AuthToken);
                this.securityContextHolderStrategy.setContext(context);
                onSuccessfulAuthentication(request, response, oAuth2AuthToken);

                this.logger.debug(LogMessage.of(() -> "SecurityContextHolder populated with remember-me token: '"
                        + this.securityContextHolderStrategy.getContext().getAuthentication() + "'"));
                this.securityContextRepository.saveContext(context, request, response);

                if (this.eventPublisher != null) {
                    this.eventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(
                            this.securityContextHolderStrategy.getContext().getAuthentication(), this.getClass()));
                }
                if(keycloackTokenExpireAt.isAfter(Instant.now())) {
                    onSuccessfulRefreshOAuth2Authentication(request, response, oAuth2AuthToken);
                }
            } catch (AuthenticationException ex) {
                this.logger.debug("Interactive login attempt was unsuccessful.");
                onLoginFail(request, response);
            }
        }
        chain.doFilter(request, response);
    }

    private void onSuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            Authentication authResult) {
    }


    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {

    }

    protected void onSuccessfulRefreshOAuth2Authentication(HttpServletRequest request, HttpServletResponse response,
                                                           Authentication authResult) throws IOException {
        OAuth2AuthToken token = (OAuth2AuthToken) authResult;
        Cookie platformCookie = new Cookie("platform", "keycloack");
        platformCookie.setPath("/");
        platformCookie.setSecure(false);
        platformCookie.setHttpOnly(false);

        Cookie accessCookie = new Cookie("accessToken", token.getAccessToken());
        accessCookie.setPath("/");
        accessCookie.setSecure(false);
        accessCookie.setHttpOnly(true);

        Cookie refreshCookie = new Cookie("refreshToken", token.getRefreshToken());
        refreshCookie.setPath("/");
        refreshCookie.setSecure(false);
        refreshCookie.setHttpOnly(true);

        Cookie oidcCookie = new Cookie("idToken", token.getIdToken());
        oidcCookie.setPath("/");
        oidcCookie.setSecure(false);
        oidcCookie.setHttpOnly(true);

        Instant instant = Instant.now().plusSeconds(parseLong(token.getExpiresIn()));
        Cookie expireAt = new Cookie("expireAt", instant.toString());
        expireAt.setPath("/");
        expireAt.setSecure(false);
        expireAt.setHttpOnly(true);

        response.addCookie(platformCookie);
        response.addCookie(accessCookie);
        response.addCookie(refreshCookie);
        response.addCookie(oidcCookie);
        response.addCookie(expireAt);
    }

    protected void onLoginFail(HttpServletRequest request, HttpServletResponse response) {
    }

    record TokenResponseBody(String access_token, String expires_in, String refresh_token, String token_type, String id_token, String notBeforePolicy, String session_state, String scope) {};
}
