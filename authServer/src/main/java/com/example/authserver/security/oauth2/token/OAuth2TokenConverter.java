package com.example.authserver.security.oauth2.token;

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

import java.util.Collections;

public class OAuth2TokenConverter implements AuthenticationConverter {
    private RestTemplate restTemplate = new RestTemplate();
    @Override
    public Authentication convert(HttpServletRequest request) {
        String code = request.getParameter("code");

        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add("grant_type", "authorization_code");
        parameters.add("code", request.getParameter("code"));
        parameters.add("redirect_uri", "http://localhost:8081/login/oauth2/code/keycloack") ;
        parameters.add("client_id", "oauth-client-app");
        parameters.add("client_secret", "LoGfkEFD09Q1bWo54sH0HlaAON9Qxsn4");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        HttpEntity<MultiValueMap<String, String>> formEntity = new HttpEntity<>(parameters, headers);

        TokenResponseBody responseBody = restTemplate
                .postForEntity(
                        "http://localhost:8080/realms/oauth2/protocol/openid-connect/token",
                        formEntity,
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
        return oAuth2AuthToken;
    }

    record TokenRequestBody(String grantType, String code, String redirectUri, String clientId, String clientSecret) {};
    record TokenResponseBody(String access_token, String expires_in, String refresh_token, String token_type, String id_token, String notBeforePolicy, String session_state, String scope) {};
}
