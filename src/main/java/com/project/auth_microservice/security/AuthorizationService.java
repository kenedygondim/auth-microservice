package com.project.auth_microservice.security;

import com.project.auth_microservice.repository.AccountAccessRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class AuthorizationService implements UserDetailsService
{
    private final AccountAccessRepository accountAccessRepository;
    @Override
    public UserDetails loadUserByUsername(String login)
    {
        UserDetails userDetails = accountAccessRepository.findByLogin(login);
        if(userDetails == null)
            throw new UsernameNotFoundException("Usuário não encontrado");
        return userDetails;
    }
}
