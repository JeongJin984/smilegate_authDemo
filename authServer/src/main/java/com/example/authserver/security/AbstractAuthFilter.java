package com.example.authserver.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public abstract class AbstractAuthFilter extends OncePerRequestFilter {
    private final AuthenticationConverter converter;
    private final RequestMatcher requestMatcher;
    private final SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
            .getContextHolderStrategy();
    private final SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();
    private final AuthenticationEntryPoint entryPoint;

    public AbstractAuthFilter(
            AuthenticationConverter converter,
            RequestMatcher requestMatcher,
            AuthenticationEntryPoint entryPoint
    ) {
        this.converter = converter;
        this.requestMatcher = requestMatcher;
        this.entryPoint = entryPoint;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            if(requestMatcher.matches(request)) {
                Authentication unAuthenticated = converter.convert(request);
                Authentication authenticated;
                if(authenticationIsRequired(unAuthenticated.getName())) {
                    authenticated = authenticate(request, response, unAuthenticated);
                    onSuccessAuthenticated(request, response, authenticated);
                }
            }
        } catch (UsernameNotFoundException usernameNotFoundException) {
            entryPoint.commence(request,response, new UsernameNotFoundException("username incorrect"));
        } catch (BadCredentialsException badCredentialsException) {
            entryPoint.commence(request,response, new BadCredentialsException("password incorrect"));
        }
        doFilter(request, response, filterChain);
    }

    public void onSuccessAuthenticated(HttpServletRequest request, HttpServletResponse response, Authentication authenticated) {
        try {
            SecurityContext context = this.securityContextHolderStrategy.createEmptyContext();
            context.setAuthentication(authenticated);
            this.securityContextHolderStrategy.setContext(context);
            this.securityContextRepository.saveContext(context, request, response);

            setCookieWithTokenInfo(response, authenticated);
        } catch (UsernameNotFoundException | IOException usernameNotFoundException) {
            usernameNotFoundException.printStackTrace();
        }
    }

    protected abstract void setCookieWithTokenInfo(
            HttpServletResponse response, Authentication authResult) throws IOException;

    protected boolean authenticationIsRequired(String username) {
        Authentication existingAuth = this.securityContextHolderStrategy.getContext().getAuthentication();
        if (existingAuth == null || !existingAuth.getName().equals(username) || !existingAuth.isAuthenticated()) {
            return true;
        }
        return (existingAuth instanceof AnonymousAuthenticationToken);
    }

    protected abstract Authentication authenticate(
            HttpServletRequest request, HttpServletResponse response, Authentication unAuthenticated
    ) throws UsernameNotFoundException;
}