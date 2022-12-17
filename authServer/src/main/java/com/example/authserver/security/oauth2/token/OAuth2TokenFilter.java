package com.example.authserver.security.oauth2.token;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.hibernate.boot.model.naming.IllegalIdentifierException;
import org.springframework.core.log.LogMessage;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class OAuth2TokenFilter extends OncePerRequestFilter {
    private final SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
            .getContextHolderStrategy();
    private AuthenticationEntryPoint authenticationEntryPoint;
    private final SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();

    private final RequestMatcher requiresAuthenticationRequestMatcher;
    private final RedisTemplate<String, Object> redisTemplate;

    private final OAuth2TokenConverter oAuth2TokenConverter = new OAuth2TokenConverter();

    public OAuth2TokenFilter(RedisTemplate<String, Object> redisTemplate) {
        this.requiresAuthenticationRequestMatcher = new AntPathRequestMatcher("/login/oauth2/code/keycloack");
        this.redisTemplate = redisTemplate;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            if(requiresAuthenticationRequestMatcher.matches(request)) {
                String state = request.getParameter("state");
                String stateValue = (String) redisTemplate.opsForValue().get(state);
                assert stateValue != null;
                redisTemplate.delete(state);

                Authentication authentication = oAuth2TokenConverter.convert(request);

                SecurityContext context = this.securityContextHolderStrategy.createEmptyContext();
                context.setAuthentication(authentication);
                this.securityContextHolderStrategy.setContext(context);
                if (this.logger.isDebugEnabled()) {
                    this.logger.debug(LogMessage.format("Set SecurityContextHolder to %s", authentication));
                }
                this.securityContextRepository.saveContext(context, request, response);

                onSuccessHandler(request, response, authentication);
            }
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        filterChain.doFilter(request, response);
    }

    private void onSuccessHandler(HttpServletRequest request, HttpServletResponse response, Authentication authResult) throws IOException {
        OAuth2AuthToken token = (OAuth2AuthToken) authResult;
        Cookie platformCookie = new Cookie("platform", "keycloack");
        platformCookie.setPath("/");
        platformCookie.setSecure(false);
        platformCookie.setHttpOnly(false);

        Cookie accessCookie = new Cookie("accessToken", token.getAccessToken());
        platformCookie.setPath("/");
        platformCookie.setSecure(false);
        platformCookie.setHttpOnly(false);

        Cookie refreshCookie = new Cookie("refreshToken", token.getRefreshToken());
        platformCookie.setPath("/");
        platformCookie.setSecure(false);
        platformCookie.setHttpOnly(false);

        Cookie oidcCookie = new Cookie("idToken", token.getIdToken());
        oidcCookie.setPath("/");
        oidcCookie.setSecure(false);
        oidcCookie.setHttpOnly(false);

        response.addCookie(platformCookie);
        response.addCookie(accessCookie);
        response.addCookie(refreshCookie);
        response.addCookie(oidcCookie);

        response.sendRedirect("http://localhost:3000");
    }
}
