package com.project.auth_microservice.controller;

import com.project.auth_microservice.dto.AccessAccountDto;
import com.project.auth_microservice.model.AccountAccess;
import com.project.auth_microservice.repository.AccountAccessRepository;
import com.project.auth_microservice.security.AuthorizationService;
import com.project.auth_microservice.security.TokenService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("bank")
public class AccountAccessController {
    private final AuthenticationManager authManager;
    private final AccountAccessRepository accountAccessRepository;
    private final TokenService tokenService;

    @Autowired
    public AccountAccessController(AuthenticationManager authManager, AccountAccessRepository accountAccessRepository, TokenService tokenService, AuthorizationService authorizationService) {
        this.authManager = authManager;
        this.accountAccessRepository = accountAccessRepository;
        this.tokenService = tokenService;
    }

    @PostMapping("/auth/login")
    public ResponseEntity<String> login(@RequestBody @Valid AccessAccountDto form) {
        AccountAccess accountAccess = accountAccessRepository.findFirstByLogin(form.login());
        if (accountAccess == null)
            throw new RuntimeException("Login inválido.");
        var accessAccountCredentials = new UsernamePasswordAuthenticationToken(form.login(), form.password());
        var auth = authManager.authenticate(accessAccountCredentials);
        var token = tokenService.generateToken((AccountAccess) auth.getPrincipal());
        return ResponseEntity.ok(token);
    }
}
