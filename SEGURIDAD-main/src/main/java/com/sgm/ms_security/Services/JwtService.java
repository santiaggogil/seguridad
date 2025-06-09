package com.sgm.ms_security.Services;

import com.sgm.ms_security.Models.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
@Service
public class JwtService {
    @Value("${jwt.secret}")
    private String secret; // Esta es la clave secreta que se utiliza para firmar el token. Debe mantenerse segura.

    @Value("${jwt.expiration}")
    private Long expiration; // Tiempo de expiración del token en milisegundos.

    private Key getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes());
    }

    public HashMap<String, Object> generateToken(User theUser) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiration);

        HashMap<String, Object> theResponse = new HashMap<>();

        String token = Jwts.builder()
                // ===== ¡EL CAMBIO CLAVE ESTÁ AQUÍ! =====
                .setSubject(theUser.getId()) // Usamos el claim estándar 'sub' para el ID
                .claim("name", theUser.getName()) // Añadimos claims adicionales
                .claim("email", theUser.getEmail())
                // Si tienes roles, también puedes añadirlos aquí:
                // .claim("role", theUser.getRole().getName())
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(getSigningKey(), SignatureAlgorithm.HS512)
                .compact();

        theResponse.put("token", token);
        theResponse.put("expiration", expiryDate);

        return theResponse;
    }

    public boolean validateToken(String token) {
        try {
            Jws<Claims> claimsJws = Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token);

            // Verifica la expiración del token
            Date now = new Date();
            return !claimsJws.getBody().getExpiration().before(now);
        } catch (SignatureException ex) {
            // La firma del token es inválida
            return false;
        } catch (Exception e) {
            // Otra excepción
            return false;
        }
    }

    public User getUserFromToken(String token) {
        try {
            Jws<Claims> claimsJws = Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token);

            Claims claims = claimsJws.getBody();

            User user = new User();
            user.set_id(claims.getSubject()); // Leer desde el claim 'sub'
            user.setName((String) claims.get("name"));
            user.setEmail((String) claims.get("email"));

            return user;
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
            System.out.println("SecretKey: " + getSigningKey());
            return null;
        }
    }

}