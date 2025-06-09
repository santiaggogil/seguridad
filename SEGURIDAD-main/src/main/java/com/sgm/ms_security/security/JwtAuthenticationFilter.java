package com.sgm.ms_security.security;

import com.sgm.ms_security.Models.User;
import com.sgm.ms_security.Services.JwtService;
import io.jsonwebtoken.JwtException; // Importante para capturar errores específicos de JWT
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus; // Necesario para devolver el código de error correcto
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtService jwtService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        try {
            // 1. Extraer el token de la cabecera "Authorization"
            String token = getTokenFromRequest(request);

            // 2. Si hay un token y es válido, autenticar al usuario
            // IMPORTANTE: Se comprueba que el usuario no esté ya autenticado en el contexto de seguridad.
            if (token != null && jwtService.validateToken(token) && SecurityContextHolder.getContext().getAuthentication() == null) {
                // 3. Obtener los datos del usuario desde el token (tu lógica original)
                User userFromToken = jwtService.getUserFromToken(token);

                if (userFromToken != null) {
                    // 4. Crear un objeto de autenticación para Spring Security (tu lógica original)
                    UserDetails userDetails = new org.springframework.security.core.userdetails.User(
                            userFromToken.getEmail(),
                            "",
                            new ArrayList<>()
                    );

                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities()
                    );

                    // 5. Establecer la autenticación en el contexto de seguridad de Spring (tu lógica original)
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }

            // 6. Continuar con el resto de la cadena de filtros SIEMPRE Y CUANDO no haya habido un error
            filterChain.doFilter(request, response);

        } catch (JwtException | IllegalArgumentException e) {
            // --- INICIO DEL CAMBIO IMPORTANTE ---
            // 7. CAPTURAR CUALQUIER ERROR DE VALIDACIÓN DEL TOKEN.
            // Esto se activa si el token está expirado, la firma es incorrecta o está malformado.
            // Tu lógica original no manejaba esto, por lo que las peticiones con tokens malos seguían su curso.

            System.err.println("Error de token JWT detectado por el filtro: " + e.getMessage());

            // 8. RESPONDER INMEDIATAMENTE CON UN ERROR 401 UNAUTHORIZED.
            // Esto le dice al cliente que su token es inválido.
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"Token inválido o expirado.\"}");

            // 9. CORTAR LA CADENA DE FILTROS.
            // Con 'return', nos aseguramos de que la petición no continúe hacia los controladores.
            // Este es el parche de seguridad crítico.
            return;
            // --- FIN DEL CAMBIO IMPORTANTE ---
        }
    }

    /**
     * Helper para extraer el token "Bearer" de la cabecera (tu lógica original, sin cambios).
     */
    private String getTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}