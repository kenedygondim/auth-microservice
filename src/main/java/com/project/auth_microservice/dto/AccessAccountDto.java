package com.project.auth_microservice.dto;
import jakarta.validation.constraints.NotBlank;


public record AccessAccountDto(
        String id,
        @NotBlank(message = "O campo de login não pode estar vazio.")
        String login,
        @NotBlank(message = "O campo de password não pode estar vazio.")
        String password
)
{
}
