package com.project.auth_microservice.enumeration;

public enum RoleEnum
{
    ADMIN("ADMIN"),
    USER("USER");

    private final String role;

    RoleEnum(String role){
        this.role = role;
    }

    public String getRole(){
        return role;
    }
}
