package com.example.authserver.security.oauth2;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Collections;

public class OAuth2AuthorizationCodeAuthenticationToken extends AbstractAuthenticationToken {
    private final String clientId;
    private final String accessToken;
    private final String refreshToken;
    private final String authorizationCode;

    public OAuth2AuthorizationCodeAuthenticationToken(String clientId, String accessToken, String refreshToken, String authorizationCode) {
        super(Collections.emptyList());
        this.clientId = clientId;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.authorizationCode = authorizationCode;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return this.clientId;
    }

    @Override
    public Object getPrincipal() {
        return this.accessToken != null ? this.accessToken : authorizationCode;
    }
}
