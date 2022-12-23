package com.example.authserver.api.service;

import com.example.authserver.data.entity.AccountInfo;
import com.example.authserver.data.repository.AccountInfoRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AccountService {
    private final AccountInfoRepository accountInfoRepository;
    private final PasswordEncoder passwordEncoder;

    public AccountInfo signup(String username, String password) {
        AccountInfo signupUser = new AccountInfo(username, passwordEncoder.encode(password));
        return accountInfoRepository.save(signupUser);
    }
}
