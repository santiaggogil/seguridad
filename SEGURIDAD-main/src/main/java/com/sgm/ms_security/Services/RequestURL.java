package com.sgm.ms_security.Services;

import com.google.gson.Gson;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class RequestURL {

    Gson gson = new Gson();
    HttpClient client = HttpClient.newHttpClient();

    public void twoFactorEmail(String twoFactorCode, String email, String name) {
        try {
            // Crear el cuerpo de la solicitud
            Map<String, Object> bodyMap = new HashMap<>();
            Map<String, String> recipient = new HashMap<>();
            recipient.put("name", name);
            recipient.put("email", email);

            List<Map<String, String>> recipients = new ArrayList<>();
            recipients.add(recipient);

            bodyMap.put("recipients", recipients);
            bodyMap.put("subject", "Tu código de autenticación de dos factores");
            bodyMap.put("content", "<h1>Código de autenticación</h1><p>Tu código de autenticación es: <strong>" + twoFactorCode + "</strong></p>");

            String body = gson.toJson(bodyMap);

            // Crear la solicitud HTTP
            HttpRequest postRequest = HttpRequest.newBuilder()
                    .uri(URI.create("http://localhost:8081/send2fa"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();

            // Enviar la solicitud y manejar la respuesta
            HttpResponse<String> response = client.send(postRequest, HttpResponse.BodyHandlers.ofString());

            // Imprimir la respuesta para depuración
            System.out.println("Response code: " + response.statusCode());
            System.out.println("Response body: " + response.body());

            if (response.statusCode() != 200) {
                throw new RuntimeException("Error al enviar el correo: " + response.body());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
