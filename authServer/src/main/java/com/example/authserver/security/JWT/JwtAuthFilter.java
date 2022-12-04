package com.example.authserver.security.JWT;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

@Component
public class JwtAuthFilter extends GenericFilterBean implements ApplicationEventPublisherAware {
    private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
            .getContextHolderStrategy();

    private SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

    private JwtAuthConverter jwtAuthConverter = new JwtAuthConverter();

    private ApplicationEventPublisher eventPublisher;

    private AuthenticationSuccessHandler successHandler;

    private AuthenticationManager authenticationManager;

    private RememberMeServices rememberMeServices;

    public JwtAuthFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
        this.rememberMeServices = null;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);

    }

    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        Authentication jwtAuthToken = jwtAuthConverter.convert(request);
        try {
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
            this.logger.debug(LogMessage
                            .format("SecurityContextHolder not populated with remember-me token, as AuthenticationManager "
                                    + "rejected Authentication returned by RememberMeServices: '%s'; "
                                    + "invalidating remember-me token", jwtAuthToken),
                    ex);
            this.logger.debug("Interactive login attempt was unsuccessful.");
            onLoginFail(request, response);
        }
        chain.doFilter(request, response);
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {

    }

    protected void onSuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                              Authentication authResult) {
    }

    protected void onLoginFail(HttpServletRequest request, HttpServletResponse response) {
    }

}
