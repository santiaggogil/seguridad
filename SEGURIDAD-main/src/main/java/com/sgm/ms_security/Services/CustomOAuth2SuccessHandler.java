package com.sgm.ms_security.Services;

import com.sgm.ms_security.Models.User;
import com.sgm.ms_security.Repositories.SessionRepository;
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

    // ===== ¡PASO 1: INYECTA EL REPOSITORIO DE SESIONES! =====
    @Autowired
    private SessionRepository theSessionRepository;

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
        System.out.println("########## 2. Datos de Google -> Email: " + email + ", Nombre: " + name + " ##########");

        // 2. Usar tu lógica existente para encontrar o crear un usuario
        User theActualUser = this.theUserRepository.getUserByEmail(email);

        if (theActualUser == null) {
            System.out.println("########## 3a. Usuario NO existe. Creando nuevo... ##########");
            // El usuario no existe, lo creamos en nuestra base de datos
            User newUser = new User();
            newUser.setEmail(email);
            newUser.setName(name);

            // IMPORTANTE: Los usuarios de OAuth no tienen contraseña.
            // Guardamos un hash de un valor aleatorio para cumplir con la restricción NOT NULL si la hubiera
            // y para asegurarnos de que no puedan hacer login con el formulario normal.
            newUser.setPassword(theEncryptionService.convertSHA256(UUID.randomUUID().toString()));
            // Aquí deberías asignar un rol por defecto si tu sistema lo requiere
            // theActualUser.setRole(defaultRole);

            theActualUser = theUserRepository.save(newUser);
            System.out.println("########## 3b. Usuario NUEVO guardado. ID asignado por DB: " + theActualUser.getId() + " ##########");

        }else {
            System.out.println("########## 3. Usuario EXISTENTE encontrado. ID: " + theActualUser.getId() + " ##########");
        }

        // VERIFICACIÓN CRÍTICA
        if (theActualUser.getId() == null || theActualUser.getId().isEmpty()) {
            System.out.println("########## ¡ERROR CRÍTICO! El ID del usuario es NULO o VACÍO antes de generar el token. ##########");
            // Aquí podrías redirigir a una página de error o lanzar una excepción para verlo claramente
            response.sendRedirect(frontendUrl + "/error?message=user_id_is_null");
            return; // Detenemos la ejecución
        }


        // 3. Generar TU PROPIO JWT usando tu servicio
        HashMap<String, Object> tokenData = theJwtService.generateToken(theActualUser);
        String token = tokenData.get("token").toString();
        System.out.println("########## 4. Token JWT generado. Comienzo del token: " + token.substring(0, 20) + "... ##########");

        // Construimos la URL base primero.
        String baseUrl = frontendUrl; // Ejemplo: "http://localhost:4200"

        // Construimos la parte del "hash" por separado, incluyendo el query parameter.
        String fragment = "/login-success?token=" + token;

        // Combinamos todo para formar la URL final.
        String targetUrl = baseUrl + "/#" + fragment;
        // =========================================================================================


        System.out.println("########## 5. Redirigiendo al frontend a la URL: " + targetUrl + " ##########\n\n\n");

        clearAuthenticationAttributes(request);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}