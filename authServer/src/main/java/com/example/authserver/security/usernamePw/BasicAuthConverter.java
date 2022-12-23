package com.example.authserver.security.usernamePw;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class BasicAuthConverter implements AuthenticationConverter {
    private final Charset credentialsCharset = StandardCharsets.UTF_8;

    private final AuthenticationDetailsSource<HttpServletRequest, ?> authDetailsSource;

    public BasicAuthConverter() {
        this(new WebAuthenticationDetailsSource());
    }

    public BasicAuthConverter(
            AuthenticationDetailsSource<HttpServletRequest, ?> authDetailsSource) {
        this.authDetailsSource = authDetailsSource;
    }

    public Charset getCredentialsCharset() {
        return this.credentialsCharset;
    }
    protected Charset getCredentialsCharset(HttpServletRequest request) {
        return getCredentialsCharset();
    }

    @Override
    public UsernamePasswordAuthenticationToken convert(HttpServletRequest request) {
        UsernamePasswordAuthenticationToken result = UsernamePasswordAuthenticationToken
                .unauthenticated(request.getParameter("username"), request.getParameter("password"));
        result.setDetails(this.authDetailsSource.buildDetails(request));
        return result;
    }
}
