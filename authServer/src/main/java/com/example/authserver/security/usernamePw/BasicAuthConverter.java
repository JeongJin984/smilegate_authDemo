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
    public static final String AUTHENTICATION_SCHEME_BASIC = "Basic";

    private Charset credentialsCharset = StandardCharsets.UTF_8;

    private AuthenticationDetailsSource<HttpServletRequest, ?> authDetailsSource;

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
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null) {
            return null;
        }
        header = header.trim();
        if (!StringUtils.startsWithIgnoreCase(header, AUTHENTICATION_SCHEME_BASIC)) {
            return null;
        }
        if (header.equalsIgnoreCase(AUTHENTICATION_SCHEME_BASIC)) {
            throw new BadCredentialsException("Empty basic authentication token");
        }
        byte[] base64Token = header.substring(6).getBytes(StandardCharsets.UTF_8);
        byte[] decoded = decode(base64Token);
        String token = new String(decoded, getCredentialsCharset(request));
        int delim = token.indexOf(":");
        if (delim == -1) {
            throw new BadCredentialsException("Invalid basic authentication token");
        }
        UsernamePasswordAuthenticationToken result = UsernamePasswordAuthenticationToken
                .unauthenticated(token.substring(0, delim), token.substring(delim + 1));
        result.setDetails(this.authDetailsSource.buildDetails(request));
        return result;
    }

    private byte[] decode(byte[] base64Token) {
        try {
            return Base64.getDecoder().decode(base64Token);
        }
        catch (IllegalArgumentException ex) {
            throw new BadCredentialsException("Failed to decode basic authentication token");
        }
    }
}
