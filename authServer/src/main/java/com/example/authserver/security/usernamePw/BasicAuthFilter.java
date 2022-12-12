package com.example.authserver.security.usernamePw;

import com.example.authserver.common.JwtUtils;
import io.jsonwebtoken.Jwts;
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
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

import static com.example.authserver.common.JwtUtils.secretKey;

public class BasicAuthFilter extends OncePerRequestFilter {

    private final SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
            .getContextHolderStrategy();
    BasicAuthConverter authenticationConverter = new BasicAuthConverter();
    private final AuthenticationManager authenticationManager;
    private AuthenticationEntryPoint authenticationEntryPoint;
    private final SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();
    private boolean ignoreFailure = false;

    public BasicAuthFilter(AuthenticationManager authenticationManager) {
        Assert.notNull(authenticationManager, "authenticationManager cannot be null");
        this.authenticationManager = authenticationManager;
        this.ignoreFailure = true;
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
        try {
            UsernamePasswordAuthenticationToken authRequest = this.authenticationConverter.convert(request);
            String username = authRequest.getName();
            if(!StringUtils.hasText(username)) {
                Cookie[] cookies = request.getCookies();
                for(Cookie cookie : cookies) {
                    if(cookie.getName().equals("accessToken")) {
                        username = Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(cookie.getValue()).getBody().getSubject();
                    }
                }
            }
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
        Cookie isAuthenticated = new Cookie("robotics", UUID.randomUUID().toString());
        isAuthenticated.setPath("/");
        isAuthenticated.setSecure(false);
        isAuthenticated.setHttpOnly(false);

        Cookie accessTokenCookie = new Cookie("accessToken", JwtUtils.createAccessToken(authResult));
        accessTokenCookie.setPath("/");
        accessTokenCookie.setSecure(false);
        accessTokenCookie.setHttpOnly(true);

        Cookie refreshTokenCookie = new Cookie("refreshToken", JwtUtils.createRefreshToken(authResult.getName()));
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setSecure(false);
        refreshTokenCookie.setHttpOnly(true);

        response.addCookie(accessTokenCookie);
        response.addCookie(refreshTokenCookie);
    }

    protected void onUnsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                                AuthenticationException failed) throws IOException {
    }

    protected boolean authenticationIsRequired(String username) {
        // Only reauthenticate if username doesn't match SecurityContextHolder and user
        // isn't authenticated (see SEC-53)
        Authentication existingAuth = this.securityContextHolderStrategy.getContext().getAuthentication();
        if (existingAuth == null || !existingAuth.getName().equals(username) || !existingAuth.isAuthenticated()) {
            return true;
        }
        // Handle unusual condition where an AnonymousAuthenticationToken is already
        // present. This shouldn't happen very often, as BasicProcessingFitler is meant to
        // be earlier in the filter chain than AnonymousAuthenticationFilter.
        // Nevertheless, presence of both an AnonymousAuthenticationToken together with a
        // BASIC authentication request header should indicate reauthentication using the
        // BASIC protocol is desirable. This behaviour is also consistent with that
        // provided by form and digest, both of which force re-authentication if the
        // respective header is detected (and in doing so replace/ any existing
        // AnonymousAuthenticationToken). See SEC-610.
        return (existingAuth instanceof AnonymousAuthenticationToken);
    }

}
