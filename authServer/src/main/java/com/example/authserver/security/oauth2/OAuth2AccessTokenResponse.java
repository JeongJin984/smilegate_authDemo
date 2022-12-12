package com.example.authserver.security.oauth2;

import org.springframework.lang.Nullable;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

public record OAuth2AccessTokenResponse (
        String accessToken,
        String refreshToken
) {

}
