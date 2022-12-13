package com.example.authserver.security.oauth2;

import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import java.util.Collection;
import java.util.Collections;

@Getter
public class OAuth2AuthorizationCodeAuthenticationToken extends AbstractAuthenticationToken {
    private final String clientId;

    private final String clientSecret;

    private final String grantType;
    private final String authorizationCode;

    private final String redirectUri;

    private String accessToken;
    private String refreshToken;

    public OAuth2AuthorizationCodeAuthenticationToken (
            String clientId,
            String clientSecret,
            String grantType,
            String authorizationCode,
            String redirectUri
    ) {
        super(Collections.emptyList());
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.grantType = grantType;
        this.authorizationCode = authorizationCode;
        this.redirectUri = redirectUri;
        setAuthenticated(false);
    }

    public OAuth2AuthorizationCodeAuthenticationToken (
            OAuth2AuthorizationCodeAuthenticationToken token,
            String accessToken,
            String refreshToken
    ) {
        super(Collections.emptyList());
        this.clientId = token.clientId;
        this.clientSecret = token.clientSecret;
        this.grantType = token.grantType;
        this.authorizationCode = token.authorizationCode;
        this.redirectUri = token.redirectUri;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
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
