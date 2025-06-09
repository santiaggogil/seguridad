package com.sgm.ms_security.Controllers;


import com.google.gson.Gson;
import com.sgm.ms_security.Models.Permission;
import com.sgm.ms_security.Models.Session;
import com.sgm.ms_security.Models.User;
import com.sgm.ms_security.Repositories.SessionRepository;
import com.sgm.ms_security.Repositories.UserRepository;
import com.sgm.ms_security.Services.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.http.HttpClient;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import com.sgm.ms_security.Services.RequestURL;


@CrossOrigin
@RestController
@RequestMapping("/api/public/security")
public class SecurityController {

    @Autowired
    private UserRepository theUserRepository;

    @Autowired
    private SessionRepository theSessionRepository;

    @Autowired
    private EncryptionService theEncryptionService;

    @Autowired
    private JwtService theJwtService;

    @Autowired
    private RequestURL theRequestURL;

    @Autowired
    private ValidatorsService theValidatorsService;

    @Autowired
    private RequestURL requestURL;

    private final HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER) // No seguir redirecciones
            .build();

    // Endpoint: /login
    @Value("${notificaciones.url}")
    private String notificacionesUrl;

    @PostMapping("/login")
    public HashMap<String, Object> login(@RequestBody User theNewUser, final HttpServletResponse response) throws IOException {
        HashMap<String, Object> theResponse = new HashMap<>();
        User theActualUser = this.theUserRepository.getUserByEmail(theNewUser.getEmail());

        if (theActualUser != null
                && theActualUser.getPassword().equals(theEncryptionService.convertSHA256(theNewUser.getPassword()))) {

            // Generar un código de dos factores
            String twoFactorCode = theEncryptionService.generateValidationCode();

            // Crear una nueva sesión
            Session newSession = new Session();
            newSession.setUser(theActualUser);
            newSession.setValidationCode(twoFactorCode);
            newSession.setExpirationDate(new Date(System.currentTimeMillis() + 3600000)); // 1 hora de expiración
            this.theSessionRepository.save(newSession);

            // No devolver la contraseña en la respuesta
            theActualUser.setPassword("");
            theResponse.put("twoFactorCode", twoFactorCode);
            theResponse.put("user", theActualUser);

            // Enviar el código de validación por correo
            try {
                // La creación del JSON con Gson sigue igual
                Map<String, String> userMap = Map.of("name", theActualUser.getName(), "email", theActualUser.getEmail());
                Map<String, Object> payload = Map.of("user", userMap, "twoFactorCode", twoFactorCode);
                Gson gson = new Gson();
                String jsonInputString = gson.toJson(payload);

                // --- Usando OkHttp para la Petición ---
                OkHttpClient client = new OkHttpClient();
                MediaType JSON = MediaType.get("application/json; charset=utf-8");

                // Esta es la línea que daba error. Debería funcionar después de recargar Maven.
                okhttp3.RequestBody body = okhttp3.RequestBody.create(jsonInputString, JSON);

                Request request = new Request.Builder()
                        .url(notificacionesUrl) // tu variable de URL
                        .post(body)
                        .build();

                // Ejecutar la llamada y obtener la respuesta
                try (Response okHttpResponse = client.newCall(request).execute()) {
                    if (!okHttpResponse.isSuccessful()) {
                        System.err.println("Error al enviar la petición con OkHttp. Código: " + okHttpResponse.code());
                        // .string() solo puede ser llamado una vez.
                        String errorBody = okHttpResponse.body() != null ? okHttpResponse.body().string() : "Sin cuerpo de respuesta.";
                        System.err.println("Cuerpo del error: " + errorBody);
                    } else {
                        String successBody = okHttpResponse.body() != null ? okHttpResponse.body().string() : "Sin cuerpo de respuesta.";
                        System.out.println("Éxito al enviar la petición con OkHttp. Respuesta: " + successBody);
                    }
                }
            } catch (Exception e) {
                // Este catch captura errores de red o de construcción de la petición
                e.printStackTrace();
            }


        } else {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
        }
        return theResponse;
    }

    // Endpoint: /login/validate/{twoFactorCode}
    @PostMapping("/login/validate/{twoFactorCode}")
    public HashMap<String, Object> validateLogin(@RequestBody User theNewUser, @PathVariable String twoFactorCode,
                                                 final HttpServletResponse response) throws IOException {
        HashMap<String, Object> theResponse = new HashMap<>();
        User theActualUser = this.theUserRepository.getUserByEmail(theNewUser.getEmail());

        // Depuración: Verificar si el usuario existe
        if (theActualUser == null) {
            System.out.println("Usuario no encontrado: " + theNewUser.getEmail());
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Usuario no encontrado");
            return theResponse;
        }

        // Depuración: Buscar sesiones asociadas al usuario
        List<Session> theSessions = theSessionRepository.getSessionByUser(theActualUser.get_id());
        System.out.println("Sesiones encontradas para el usuario: " + theSessions);

        // Validar el código de dos factores
        Session validSession = null;
        for (Session session : theSessions) {
            System.out.println("Validando sesión: " + session.get_id());
            System.out.println("Código almacenado: " + session.getValidationCode());
            System.out.println("Código proporcionado: " + twoFactorCode);
            if (session.getValidationCode().equals(twoFactorCode)) {
                validSession = session;
                break;
            }
        }

        if (validSession == null) {
            System.out.println("Código de dos factores incorrecto para el usuario: " + theNewUser.getEmail());
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Código de dos factores incorrecto");
            return theResponse;
        }

        // Generar el token JWT
        HashMap<String, Object> tokenResponse = theJwtService.generateToken(theActualUser);
        String token = tokenResponse.get("token").toString();
        Date expirationDate = (Date) tokenResponse.get("expiration");

        // Actualizar la sesión con el token
        validSession.setValidationCode(""); // Limpiar el código de validación
        validSession.setToken(token);
        validSession.setExpirationDate(expirationDate);
        this.theSessionRepository.save(validSession);

        // No devolver la contraseña en la respuesta
        theActualUser.setPassword("");
        theResponse.put("user", theActualUser);
        theResponse.put("token", token);
        theResponse.put("expiration", expirationDate);

        return theResponse;
    }

    // Endpoint: /login-no-auth
    @PostMapping("/login-no-auth")
    public HashMap<String, Object> loginNoAuth(@RequestBody User theNewUser, final HttpServletResponse response) throws IOException {
        HashMap<String, Object> theResponse = new HashMap<>();
        User theActualUser = this.theUserRepository.getUserByEmail(theNewUser.getEmail());

        if (theActualUser != null
                && theActualUser.getPassword().equals(theEncryptionService.convertSHA256(theNewUser.getPassword()))) {

            String token = theJwtService.generateToken(theActualUser).get("token").toString();
            theActualUser.setPassword(""); // No devolver la contraseña
            theResponse.put("token", token);
            theResponse.put("user", theActualUser);
        } else {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
        }
        return theResponse;
    }

    // Método auxiliar: Validación de dos factores
    private boolean twoFactorValidation(User theActualUser, String twoFactorCode) {
        List<Session> theSessions = theSessionRepository.getSessionByUser(theActualUser.get_id());
        for (Session session : theSessions) {
            if (session.getValidationCode().equals(twoFactorCode)) {
                return true;
            }
        }
        return false;
    }

    // Endpoint: /permissions-validation
    @PostMapping("/permissions-validation")
    public boolean permissionsValidation(final HttpServletRequest request, @RequestBody Permission thePermission) {
        return this.theValidatorsService.validationRolePermission(request, thePermission.getUrl(), thePermission.getMethod());
    }

    // Endpoint: /{userId}/matchSession/{sessionId}
    @PutMapping("/{userId}/matchSession/{sessionId}")
    public String matchSession(@PathVariable String userId, @PathVariable String sessionId) {
        User theActualUser = this.theUserRepository.findById(userId).orElse(null);
        Session theActualSession = this.theSessionRepository.findById(sessionId).orElse(null);

        if (theActualUser != null && theActualSession != null) {
            theActualSession.setUser(theActualUser);
            this.theSessionRepository.save(theActualSession);
            return "Session matched to user successfully";
        } else {
            return "User or session not found";
        }
    }

    // Endpoint: /{userId}/unmatchSession/{sessionId}
    @PutMapping("/{userId}/unmatchSession/{sessionId}")
    public String unmatchSession(@PathVariable String userId, @PathVariable String sessionId) {
        Session theActualSession = this.theSessionRepository.findById(sessionId).orElse(null);

        if (theActualSession != null && theActualSession.getUser() != null && theActualSession.getUser().get_id().equals(userId)) {
            theActualSession.setUser(null);
            this.theSessionRepository.save(theActualSession);
            return "Session unmatched from user successfully";
        } else {
            return "User or session not found";
        }
    }

    // ===== ¡NUEVO ENDPOINT! =====
    @PostMapping("/forgot-password")
    public ResponseEntity<Map<String, String>> forgotPassword(@RequestBody Map<String, String> body) {
        String email = body.get("email");
        User currentUser = this.theUserRepository.getUserByEmail(email);

        if (currentUser == null) {
            // Por seguridad, no revelamos si el correo existe o no.
            return ResponseEntity.ok(Map.of("message", "Si el correo está registrado, recibirás una nueva contraseña."));
        }

        try {
            // 1. Generar contraseña aleatoria (método de tu ejemplo)
            String generatedPassword = generateRandomPassword(12);

            // 2. Encriptar y guardar la nueva contraseña
            currentUser.setPassword(theEncryptionService.convertSHA256(generatedPassword));
            this.theUserRepository.save(currentUser);

            // 3. Enviar la contraseña por correo usando tu servicio de notificaciones
            this.requestURL.sendNewPasswordByEmail(currentUser.getEmail(), currentUser.getName(), generatedPassword);

            return ResponseEntity.ok(Map.of("message", "Si el correo está registrado, recibirás una nueva contraseña."));

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Error al procesar la solicitud."));
        }
    }

    private String generateRandomPassword(int length) {
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder password = new StringBuilder(length);
        java.security.SecureRandom random = new java.security.SecureRandom();
        for (int i = 0; i < length; i++) {
            int index = random.nextInt(characters.length());
            password.append(characters.charAt(index));
        }
        return password.toString();
    }
}
