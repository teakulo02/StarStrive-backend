package com.starstrive.starstrive.configuration;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import static com.starstrive.starstrive.enums.Permission.*;
import static com.starstrive.starstrive.enums.Role.*;
import static org.springframework.http.HttpMethod.*;
import static org.springframework.http.HttpMethod.DELETE;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfiguration {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    private final LogoutHandler logoutHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf()
                .disable()
                .authorizeHttpRequests()
                .requestMatchers("/api/auth/**")
                .permitAll()
                .requestMatchers("/api/home/**").hasAnyRole(USER.name(), TEACHER.name(), ADMIN.name())
                .requestMatchers("/api/teacher/**").hasAnyRole(ADMIN.name(), TEACHER.name())

                .requestMatchers(GET, "/api/teacher/**").hasAnyAuthority(ADMIN_READ.name(), TEACHER_READ.name())
                .requestMatchers(POST, "/api/teacher/**").hasAnyAuthority(ADMIN_CREATE.name(), TEACHER_CREATE.name())
                .requestMatchers(PUT, "/api/teacher/**").hasAnyAuthority(ADMIN_UPDATE.name(), TEACHER_UPDATE.name())
                .requestMatchers(DELETE, "/api/teacher/**").hasAnyAuthority(ADMIN_DELETE.name(), TEACHER_DELETE.name())

                .requestMatchers("/api/admin/**").hasRole(ADMIN.name())

//                .requestMatchers(GET, "/api/admin/**").hasAuthority(ADMIN_READ.name())
//                .requestMatchers(POST, "/api/admin/**").hasAuthority(ADMIN_CREATE.name())
//                .requestMatchers(PUT, "/api/admin/**").hasAuthority(ADMIN_UPDATE.name())
//                .requestMatchers(DELETE, "/api/admin/**").hasAuthority(ADMIN_DELETE.name())


                .anyRequest()
                .authenticated()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .logout()
                .logoutUrl("/api/auth/logout")
                .addLogoutHandler(logoutHandler)
                .logoutSuccessHandler((request, response, authentication) ->
                        SecurityContextHolder.clearContext()
                );

        return http.build();
    }
}
