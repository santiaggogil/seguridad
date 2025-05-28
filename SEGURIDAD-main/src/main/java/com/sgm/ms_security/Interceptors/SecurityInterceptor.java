package com.sgm.ms_security.Interceptors;

import com.sgm.ms_security.Models.Role;
import com.sgm.ms_security.Models.UserRole;
import com.sgm.ms_security.Repositories.RoleRepository;
import com.sgm.ms_security.Repositories.UserRoleRepository;
import com.sgm.ms_security.Services.ValidatorsService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import java.util.Optional;

@Component
public class SecurityInterceptor implements HandlerInterceptor {
    @Autowired
    private ValidatorsService validatorService;
    @Override
    public boolean preHandle(HttpServletRequest request,
                             HttpServletResponse response,
                             Object handler) throws Exception {

        System.out.println("INGRESA");
        String authHeader = request.getHeader("Authorization");

        boolean succes = this.validatorService.validationRolePermission(request, request.getRequestURI(), request.getMethod());

        System.out.println("Interceptor: " + request.getHeader("Authorization"));
        System.out.println("Interceptor: " + request.getRequestURI());
        System.out.println("Interceptor: " + request.getMethod());
        System.out.println("Interceptor: " + succes);

        return succes;
    }


    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler,
                                Exception ex) throws Exception {
        // Lógica a ejecutar después de completar la solicitud, incluso después de la renderización de la vista
    }
}