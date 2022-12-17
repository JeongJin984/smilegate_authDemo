package com.example.authserver.security.oauth2.token;

import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

@Getter
public class OAuth2AuthToken extends AbstractAuthenticationToken {
    private String accessToken;
    private String expiresIn;
    private String refreshToken;
    private String tokenType;
    private String idToken;
    private String scope;

    public OAuth2AuthToken(Collection<? extends GrantedAuthority> authorities, String accessToken, String expiresIn, String refreshToken, String tokenType, String idToken, String scope) {
        super(authorities);
        this.accessToken = accessToken;
        this.expiresIn = expiresIn;
        this.refreshToken = refreshToken;
        this.tokenType = tokenType;
        this.idToken = idToken;
        this.scope = scope;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return idToken;
    }
}
