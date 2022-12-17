package com.example.resourceserver.security.JWT;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.time.Instant;
import java.util.Collections;

public class OAuth2TokenConverter implements AuthenticationConverter {
    private RestTemplate restTemplate = new RestTemplate();
    @Override
    public Authentication convert(HttpServletRequest request) {
        Instant keycloackTokenExpireAt = null;
        String refreshToken = null;
        String accessToken = null;
        String idToken = null;
        for(Cookie cookie : request.getCookies()) {
            if(cookie.getName().equals("expireAt")) {
                keycloackTokenExpireAt = Instant.parse(cookie.getValue());
            } else if(cookie.getName().equals("refreshToken")) {
                refreshToken = cookie.getValue();
            } else if(cookie.getName().equals("accessToken")) {
                accessToken = cookie.getValue();
            } else if(cookie.getName().equals("idToken")) {
                idToken = cookie.getValue();
            }
        }

        assert keycloackTokenExpireAt != null;
        assert refreshToken != null;
        if(keycloackTokenExpireAt.isAfter(Instant.now())) {
            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            params.add("grant_type", "refresh_token");
            params.add("client_id", "oauth-client-app");
            params.add("client_secret", "LoGfkEFD09Q1bWo54sH0HlaAON9Qxsn4");
            params.add("refresh_token", refreshToken);

            HttpHeaders headers = new HttpHeaders();
            headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
            final MediaType contentType = MediaType.valueOf(MediaType.APPLICATION_FORM_URLENCODED_VALUE + ";charset=UTF-8");
            headers.setContentType(contentType);

            HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(params, headers);

            TokenResponseBody responseBody = restTemplate.postForEntity(
                    "http://localhost:8080/realms/oauth2/protocol/openid-connect/token",
                    entity,
                    TokenResponseBody.class
            ).getBody();

            assert responseBody != null;

            OAuth2AuthToken oAuth2AuthToken = new OAuth2AuthToken(
                    AuthorityUtils.createAuthorityList("ROLE_USER"),
                    responseBody.access_token,
                    responseBody.expires_in,
                    responseBody.refresh_token,
                    responseBody.token_type,
                    responseBody.id_token,
                    responseBody.scope
            );
            oAuth2AuthToken.setAuthenticated(true);
            return oAuth2AuthToken;
        }
        return new OAuth2AuthToken(
                AuthorityUtils.createAuthorityList("ROLE_USER"),
                accessToken,
                keycloackTokenExpireAt.toString(),
                refreshToken, "Bearer",
                idToken,
                "openid email profile"
        );
    }

    record TokenRequestBody(String grantType, String code, String redirectUri, String clientId, String clientSecret) {};
    record TokenResponseBody(String access_token, String expires_in, String refresh_token, String token_type, String id_token, String notBeforePolicy, String session_state, String scope) {};
}
