package com.sgm.ms_security.Controllers;

import com.sgm.ms_security.Models.Role;
import com.sgm.ms_security.Models.User;
import com.sgm.ms_security.Models.UserRole;
import com.sgm.ms_security.Repositories.RoleRepository;
import com.sgm.ms_security.Repositories.UserRepository;
import com.sgm.ms_security.Repositories.UserRoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@CrossOrigin
@RestController
@RequestMapping("api/usersroles")
public class UsersRolesControllers {
    @Autowired
    UserRoleRepository theUserRoleRepository;
    @Autowired
    UserRepository theUserRepository;
    @Autowired
    RoleRepository theRoleRepository;

    @GetMapping("/all")
    public ResponseEntity<?> getAll(){
        return ResponseEntity.ok(this.theUserRoleRepository.findAll());
    }

    @GetMapping("/user/{userId}")
    public List<Role> getRolesByUserId(@PathVariable String userId) {
        // Extract the roles from the user roles
        List<UserRole> theUsersRoles = this.theUserRoleRepository.getRolesByUserId(userId);

        return theUsersRoles.stream()
                .map(UserRole::getRole)
                .collect(Collectors.toList());
    }

    @GetMapping("/role/{roleId}")
    public List<User> getUsersByRoleId(@PathVariable String roleId) {
        // Extract the users from the user roles
        List<UserRole> theUsersRoles = this.theUserRoleRepository.getUsersByRoleId(roleId);

        return  theUsersRoles.stream()
                .map(UserRole::getUser)
                .collect(Collectors.toList());
    }

    @PostMapping("/user/{userId}/role/{roleId}")
    public ResponseEntity<?> create(@PathVariable String userId, @PathVariable String roleId){
        User theUser = this.theUserRepository.findById(userId).orElse(null);
        Role theRole = this.theRoleRepository.findById(roleId).orElse(null);

        if (theUser != null && theRole != null) {
            UserRole newUserRole = new UserRole();

            newUserRole.setUser(theUser);
            newUserRole.setRole(theRole);
            return ResponseEntity.ok(this.theUserRoleRepository.save(newUserRole));
        }

        return ResponseEntity.status(404).body("No se encontró el usuario o el rol");
    }

    @DeleteMapping
    public void delete(@PathVariable String id){
        this.theUserRoleRepository.findById(id).ifPresent(theUserRole -> this.theUserRoleRepository.delete(theUserRole));
    }
}