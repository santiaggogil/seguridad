package com.sgm.ms_security.Configurations;

import com.sgm.ms_security.Services.CustomOAuth2SuccessHandler;
import com.sgm.ms_security.security.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import java.util.Arrays;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private CustomOAuth2SuccessHandler customOAuth2SuccessHandler;

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Desactiva la protección CSRF, común en APIs stateless
                .csrf(csrf -> csrf.disable())

                // Habilita CORS usando la configuración del Bean 'corsConfigurationSource'
                .cors(Customizer.withDefaults())

                // Establece la política de sesión como STATELESS.
                // Esto es FUNDAMENTAL para una API basada en JWT.
                // Spring no creará ni usará sesiones HttpSession.
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Configura las reglas de autorización para las peticiones HTTP
                .authorizeHttpRequests(auth -> auth
                        // Define las rutas públicas que no requieren autenticación
                        .requestMatchers(
                                "/api/public/security/**", // Tu API de login/registro normal
                                "/oauth2/**",               // El flujo de inicio de OAuth2
                                "/login/**",
                                "/api/public/**"
                                // La URL de callback de OAuth2
                        ).permitAll()
                        // Cualquier otra petición (ej. /api/users, /api/dashboard) requiere autenticación
                        .anyRequest().authenticated()
                )

                // Configura el login con OAuth2 (Google, etc.)
                .oauth2Login(oauth2 -> oauth2
                        // Tu configuración de endpoints está bien, aunque los defaults suelen funcionar
                        .authorizationEndpoint(endpoint -> endpoint
                                .baseUri("/oauth2/authorization")
                        )
                        .redirectionEndpoint(endpoint -> endpoint
                                .baseUri("/login/oauth2/code/*")
                        )
                        // Tu handler personalizado para crear el JWT y redirigir al frontend
                        .successHandler(customOAuth2SuccessHandler)
                )

                // ¡LA PIEZA FINAL!
                // Añade tu filtro de validación de JWT a la cadena de seguridad de Spring.
                // Se ejecutará ANTES del filtro de autenticación estándar.
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // ===== AÑADE ESTE MÉTODO COMPLETO =====
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // Especifica el origen de tu frontend. ¡No uses "*" si necesitas credenciales!
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:4200")); // O la URL de tu frontend en producción

        // Métodos HTTP permitidos
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));

        // Cabeceras permitidas (puedes ser más específico si quieres)
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "X-Requested-With", "Accept"));

        // ¡LA LÍNEA MÁS IMPORTANTE PARA OAUTH2 y SESIONES!
        // Permite que el navegador envíe cookies y cabeceras de autorización.
        configuration.setAllowCredentials(true);

        // Tiempo que el navegador puede cachear la respuesta pre-flight de CORS
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // Aplica esta configuración a todas las rutas de tu API
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }
}