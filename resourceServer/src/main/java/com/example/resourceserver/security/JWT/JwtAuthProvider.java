package com.example.resourceserver.security.JWT;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;

public class JwtAuthProvider implements AuthenticationProvider {

    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        JwtAuthToken authToken = (JwtAuthToken) authentication;

        return authentication;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthToken.class.isAssignableFrom(authentication);
    }
}
