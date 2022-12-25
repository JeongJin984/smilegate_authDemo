package com.example.authserver.security.usernamePw;

import com.example.authserver.data.entity.AccountInfo;
import com.example.authserver.data.repository.AccountInfoRepository;
import com.example.authserver.security.dto.AccountDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


@Service
@RequiredArgsConstructor
public class BasicUserDetailsService implements UserDetailsService {

    private final AccountInfoRepository accountInfoRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AccountInfo account = accountInfoRepository.findAccountInfoByUsername(username);
        if(account == null) {
            throw new UsernameNotFoundException("Invalid username");
        }
        return new AccountDetails(account.getUsername(), account.getPassword());
    }
}
