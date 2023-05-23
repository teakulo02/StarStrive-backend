package com.starstrive.starstrive.controllers.auth;

import com.starstrive.starstrive.enums.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {

    private String firstname;
    private String lastname;
    private String nickname;
    private String email;
    private String password;
    private Role role;
}