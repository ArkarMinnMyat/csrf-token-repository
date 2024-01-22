package com.example.csrftokenrepository.config;

import com.example.csrftokenrepository.csrf.CustomCsrfRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomCsrfRepository customCsrfRepository;
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        http.csrf(c -> {
            c.csrfTokenRepository(customCsrfRepository);
            c.csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler());

        });

        http.authorizeHttpRequests( c ->
                c.anyRequest().permitAll());
        return http.build();
    }
}
