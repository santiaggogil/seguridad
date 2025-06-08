package com.sgm.ms_security.Services;

import com.sgm.ms_security.Models.User;
import com.sgm.ms_security.Repositories.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.HashMap;
import java.util.UUID;

@Component
public class CustomOAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    @Autowired
    private JwtService theJwtService; // ¡Tu servicio de JWT existente!

    @Autowired
    private UserRepository theUserRepository; // ¡Tu repositorio de usuarios existente!

    @Autowired
    private EncryptionService theEncryptionService; // ¡Tu servicio de encriptación!

    @Value("${app.frontend.url}")
    private String frontendUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // ==== ¡LA LÍNEA DE PRUEBA! ====
        System.out.println("¡ÉXITO! CustomOAuth2SuccessHandler SE ESTÁ EJECUTANDO.");
        //

        // 1. Obtener los datos del usuario del proveedor OAuth2 (Google/Microsoft)
        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
        String email = oauth2User.getAttribute("email");
        String name = oauth2User.getAttribute("name");

        // 2. Usar tu lógica existente para encontrar o crear un usuario
        User theActualUser = this.theUserRepository.getUserByEmail(email);

        if (theActualUser == null) {
            // El usuario no existe, lo creamos en nuestra base de datos
            theActualUser = new User();
            theActualUser.setEmail(email);
            theActualUser.setName(name);
            // IMPORTANTE: Los usuarios de OAuth no tienen contraseña.
            // Guardamos un hash de un valor aleatorio para cumplir con la restricción NOT NULL si la hubiera
            // y para asegurarnos de que no puedan hacer login con el formulario normal.
            theActualUser.setPassword(theEncryptionService.convertSHA256(UUID.randomUUID().toString()));

            // Aquí deberías asignar un rol por defecto si tu sistema lo requiere
            // theActualUser.setRole(defaultRole);

            theUserRepository.save(theActualUser);
        }

        // 3. Generar TU PROPIO JWT usando tu servicio
        HashMap<String, Object> tokenData = theJwtService.generateToken(theActualUser);
        String token = tokenData.get("token").toString();

        // 4. Preparar la URL de redirección al frontend, incluyendo el token
        String targetUrl = UriComponentsBuilder.fromUriString(frontendUrl + "/login-success")
                .queryParam("token", token)
                .build().toUriString();

        // Limpiamos los atributos de la sesión para evitar conflictos
        clearAuthenticationAttributes(request);

        // 5. Redirigir al frontend
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}