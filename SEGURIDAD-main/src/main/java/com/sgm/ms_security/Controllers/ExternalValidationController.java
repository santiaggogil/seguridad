package com.sgm.ms_security.Controllers;

import com.sgm.ms_security.Services.JwtService; // <--- AÑADIR ESTE IMPORT
import com.sgm.ms_security.Services.ValidatorsService;
import io.jsonwebtoken.JwtException; // <--- AÑADIR ESTE IMPORT
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@CrossOrigin
@RestController
@RequestMapping("/external-auth")
public class ExternalValidationController {

    @Autowired
    private ValidatorsService theValidatorsService;

    // INYECTAMOS EL SERVICIO DE JWT DIRECTAMENTE AQUÍ
    @Autowired
    private JwtService jwtService;

    @GetMapping("/validate")
    public ResponseEntity<?> validatePermissions( // Cambiado a ResponseEntity<?> para devolver cuerpos de error
                                                  HttpServletRequest request,
                                                  @RequestHeader("X-Requested-Path") String path,
                                                  @RequestHeader("X-Requested-Method") String method
    ) {

        // --- INICIO DE LA BARRERA DE ACERO ---
        // 1. EXTRAER EL TOKEN. SIN EXCUSAS.
        final String authHeader = request.getHeader("Authorization");

        // 2. SI NO HAY TOKEN O NO EMPIEZA CON "Bearer ", ES 401. FIN DE LA DISCUSIÓN.
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return new ResponseEntity<>("{\"error\": \"Token de autorización no proporcionado o malformado\"}", HttpStatus.UNAUTHORIZED);
        }

        final String token = authHeader.substring(7);

        // 3. VALIDAR QUE EL TOKEN SEA REAL. SI NO, ES 401. FIN DE LA DISCUSIÓN.
        try {
            if (!jwtService.validateToken(token)) {
                // Esto cubre casos como expiración que no lanzan excepción pero devuelven false.
                return new ResponseEntity<>("{\"error\": \"Token inválido\"}", HttpStatus.UNAUTHORIZED);
            }
        } catch (JwtException | IllegalArgumentException e) {
            // Esto cubre tokens con firma incorrecta, malformados o cualquier otro error de la librería JWT.
            return new ResponseEntity<>("{\"error\": \"Token no válido: " + e.getMessage() + "\"}", HttpStatus.UNAUTHORIZED);
        }
        // --- FIN DE LA BARRERA DE ACERO ---


        // --- SI LLEGAMOS AQUÍ, EL TOKEN ES 100% VÁLIDO EN FIRMA Y EXPIRACIÓN ---
        // 4. AHORA, Y SÓLO AHORA, VERIFICAMOS LOS PERMISOS.
        boolean hasPermission = this.theValidatorsService.validationRolePermission(request, path, method);

        if (hasPermission) {
            // 5. EL TOKEN ES VÁLIDO Y TIENE PERMISOS. DEVOLVEMOS 200 OK.
            return ResponseEntity.ok().build();
        } else {
            // 6. EL TOKEN ES VÁLIDO PERO EL USUARIO NO TIENE PERMISOS. DEVOLVEMOS 403 FORBIDDEN.
            return new ResponseEntity<>("{\"error\": \"El usuario no tiene permisos para realizar esta acción\"}", HttpStatus.FORBIDDEN);
        }
    }
}