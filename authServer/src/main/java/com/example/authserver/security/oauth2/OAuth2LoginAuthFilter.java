package com.example.authserver.security.oauth2;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import java.io.IOException;

public class OAuth2LoginAuthFilter extends AbstractAuthenticationProcessingFilter {
    private AuthenticationManager authenticationManager;
    private OAuth2LoginAuthProvider oAuth2LoginAuthProvider;

    public OAuth2LoginAuthFilter(AuthenticationManager authenticationManager) {
        super("/login/oauth2/code/*");
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        oAuth2LoginAuthProvider.authenticate()
        return null;
    }
}
