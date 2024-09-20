package com.project.auth_microservice.repository;

import com.project.auth_microservice.model.AccountAccess;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Repository;

@Repository
public interface AccountAccessRepository extends JpaRepository<AccountAccess, Long>
{
    UserDetails findByLogin(String login);
    AccountAccess findFirstByLogin(String login);
}
