package com.sgm.ms_security.Configurations;

import com.sgm.ms_security.Services.CustomOAuth2SuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private CustomOAuth2SuccessHandler customOAuth2SuccessHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .cors(Customizer.withDefaults()) // Asegúrate de tener la configuración de CORS

                // ESTA ES LA SECCIÓN QUE CAMBIA
                // No vamos a forzar STATELESS aquí. Dejaremos que Spring maneje la sesión
                // durante el login, y nuestro JWT se encargará de que el resto sea stateless.

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/public/security/**", "/oauth2/**", "/login/oauth2/code/**").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                        .authorizationEndpoint(endpoint -> endpoint
                                // Le decimos a Spring dónde empezar el flujo
                                .baseUri("/oauth2/authorization")
                        )
                        .redirectionEndpoint(endpoint -> endpoint
                                // Le decimos a Spring dónde esperar la respuesta de Google
                                .baseUri("/login/oauth2/code/*")
                        )
                        .successHandler(customOAuth2SuccessHandler) // ¡Aquí está nuestro handler!
                );

        return http.build();
    }
}