package com.example.authserver.security.usernamePw;

import com.example.authserver.common.DefaultJwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Random;

import static com.example.authserver.common.jwtUtils.Variables.accessTokenKey;
import static com.example.authserver.common.jwtUtils.Variables.refreshTokenKey;

public class BasicAuthFilter extends OncePerRequestFilter {

    private final SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
            .getContextHolderStrategy();
    BasicAuthConverter authenticationConverter = new BasicAuthConverter();
    private final AuthenticationManager authenticationManager;
    private AuthenticationEntryPoint authenticationEntryPoint;
    private final SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();

    private RequestMatcher requiresAuthenticationRequestMatcher;
    private boolean ignoreFailure = false;

    public BasicAuthFilter(AuthenticationManager authenticationManager) {
        Assert.notNull(authenticationManager, "authenticationManager cannot be null");
        this.authenticationManager = authenticationManager;
        this.ignoreFailure = true;
        requiresAuthenticationRequestMatcher = new AntPathRequestMatcher("/login/jwt/*");
    }

    public BasicAuthFilter(AuthenticationManager authenticationManager,
                            AuthenticationEntryPoint authenticationEntryPoint) {
        Assert.notNull(authenticationManager, "authenticationManager cannot be null");
        Assert.notNull(authenticationEntryPoint, "authenticationEntryPoint cannot be null");

        this.authenticationManager = authenticationManager;
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        if(!requiresAuthenticationRequestMatcher.matches(request)) {
            doFilter(request,response,chain);
            return;
        }

        try {
            UsernamePasswordAuthenticationToken authRequest = this.authenticationConverter.convert(request);
            if (authRequest == null) {
                this.logger.trace("Did not process authentication request since failed to find "
                        + "username and password in Basic Authorization header");
                chain.doFilter(request, response);
                return;
            }
            String username = authRequest.getName();
            this.logger.trace(LogMessage.format("Found username '%s' in Basic Authorization header", username));
            if (authenticationIsRequired(username)) {
                Authentication authResult = this.authenticationManager.authenticate(authRequest);
                SecurityContext context = this.securityContextHolderStrategy.createEmptyContext();
                context.setAuthentication(authResult);
                this.securityContextHolderStrategy.setContext(context);
                if (this.logger.isDebugEnabled()) {
                    this.logger.debug(LogMessage.format("Set SecurityContextHolder to %s", authResult));
                }
                this.securityContextRepository.saveContext(context, request, response);
                onSuccessfulAuthentication(request, response, authResult);
            }
        }
        catch (AuthenticationException ex) {
            this.logger.debug("Failed to process authentication request", ex);
            onUnsuccessfulAuthentication(request, response, ex);
            if (this.ignoreFailure) {
                chain.doFilter(request, response);
            }
            else {
                // handle failure ( like adding unauthorized status, header)
                this.authenticationEntryPoint.commence(request, response, ex);
            }
            return;
        }

        chain.doFilter(request, response);
    }

    protected void onSuccessfulAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authResult
    ) throws IOException {
        Cookie loginPlatform = new Cookie("platform", "JWT");
        loginPlatform.setPath("/");
        loginPlatform.setSecure(false);
        loginPlatform.setHttpOnly(true);

        DefaultJwtBuilder jwtBuilder = new DefaultJwtBuilder("accessToken");
        jwtBuilder.setHeader("alg", SignatureAlgorithm.forSigningKey(accessTokenKey).getValue());
        jwtBuilder.setHeader("typ", "JWT");
        jwtBuilder.setPayload("iss", "sMilestone", "registered");
        jwtBuilder.setPayload("sub", authResult.getName(), "registered");
        jwtBuilder.setPayload("aud", authResult.getName(), "registered");
        jwtBuilder.setPayload("exp", (LocalDateTime.now().plusSeconds(1L)).toString(), "registered");
        jwtBuilder.setPayload("iat", LocalDateTime.now().toString(), "registered");
        jwtBuilder.setPayload("token_type", "accessToken", "public");

        Cookie accessTokenCookie = new Cookie("accessToken", jwtBuilder.compact());
        accessTokenCookie.setPath("/");
        accessTokenCookie.setSecure(false);
        accessTokenCookie.setHttpOnly(true);

        jwtBuilder = new DefaultJwtBuilder("refreshToken");
        jwtBuilder.setHeader("alg", SignatureAlgorithm.forSigningKey(refreshTokenKey).getValue());
        jwtBuilder.setHeader("typ", "JWT");
        jwtBuilder.setPayload("iss", "sMilestone", "registered");
        jwtBuilder.setPayload("sub", authResult.getName(), "registered");
        jwtBuilder.setPayload("aud", authResult.getName(), "registered");
        jwtBuilder.setPayload("exp", (LocalDateTime.now().plusWeeks(5L)).toString(), "registered");
        jwtBuilder.setPayload("iat", LocalDateTime.now().toString(), "registered");
        jwtBuilder.setPayload("token_type", "refreshToken", "public");

        Cookie refreshTokenCookie = new Cookie("refreshToken", jwtBuilder.compact());
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setSecure(false);
        refreshTokenCookie.setHttpOnly(true);

        response.addCookie(loginPlatform);
        response.addCookie(accessTokenCookie);
        response.addCookie(refreshTokenCookie);
    }

    protected void onUnsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                                AuthenticationException failed) throws IOException {
    }

    protected boolean authenticationIsRequired(String username) {
        Authentication existingAuth = this.securityContextHolderStrategy.getContext().getAuthentication();
        if (existingAuth == null || !existingAuth.getName().equals(username) || !existingAuth.isAuthenticated()) {
            return true;
        }
        return (existingAuth instanceof AnonymousAuthenticationToken);
    }
}
