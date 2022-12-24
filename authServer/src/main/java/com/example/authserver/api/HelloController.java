package com.example.authserver.api;

import com.example.authserver.api.service.AccountService;
import com.example.authserver.common.DefaultJwtBuilder;
import com.example.authserver.common.DefaultJwtParser;
import com.example.authserver.data.entity.AccountInfo;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Map;

import static com.example.authserver.common.jwtUtils.Variables.accessTokenSecretKey;

@RestController
@RequiredArgsConstructor
public class HelloController {
    private final AccountService accountService;
    private final RedisTemplate<String, Object> redisTemplate;

    @GetMapping("/hello/")
    public String helloGet() {
        return "Hello Get";
    }

    @PostMapping("/login/jwt/")
    public String helloPost() {
        return "Login Succeed!!!";
    }

    @GetMapping("/jwt/refresh/")
    public ResponseEntity<Map<String, String>> getValidAccessToken(HttpServletRequest request) throws IllegalAccessException {
        String accessToken = request.getHeader(HttpHeaders.AUTHORIZATION);
        String refreshToken = request.getHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS);

        Map<String, ?> accessTokenPayload = new DefaultJwtParser().getPayload(accessToken);

        DefaultJwtParser jwtParser = new DefaultJwtParser();

        String refreshTokenState = (String) redisTemplate.opsForValue().get(refreshToken);
        if(StringUtils.hasText(refreshTokenState)) {
            throw new IllegalAccessException("Invalid Refresh Token");
        }

        if(jwtParser.isExpiredToken(accessToken)) {
            if(!jwtParser.isExpiredToken(refreshToken)) {
                jwtParser.validateToken(accessToken, "accessToken");
                jwtParser.validateToken(refreshToken, "refreshToken");

                DefaultJwtBuilder jwtBuilder = new DefaultJwtBuilder(accessTokenSecretKey);
                jwtBuilder.setHeader("alg", "HS256");
                jwtBuilder.setHeader("typ", "JWT");
                jwtBuilder.setPayload("iss", "sMilestone", "registered");
                jwtBuilder.setPayload("sub", (String) accessTokenPayload.get("aud"), "registered");
                jwtBuilder.setPayload("aud", (String) accessTokenPayload.get("aud"), "registered");
                jwtBuilder.setPayload("exp", (LocalDateTime.now().plusMinutes(5L)).toString(), "registered");
                jwtBuilder.setPayload("iat", LocalDateTime.now().toString(), "registered");
                jwtBuilder.setPayload("token_type", "accessToken", "public");

                accessToken = jwtBuilder.compact();
            } else {
                return new ResponseEntity<>(Map.of("message", "Refresh Token Expired"), HttpStatus.BAD_REQUEST);
            }
        }
         return new ResponseEntity<>(Map.of("accessToken", accessToken), HttpStatus.OK);
    }

    @PostMapping("/signup/")
    public AccountInfo signup(@RequestBody SignupRequestBody requestBody) {
        return accountService.signup(requestBody.username, requestBody.password);
    }

    @GetMapping("/login/oauth2/code/keycloack")
    public String redirect() {
        return "hello";
    }

    record SignupRequestBody(String username, String password) {}
}
