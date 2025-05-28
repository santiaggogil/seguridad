package com.sgm.ms_security.Controllers;

import com.sgm.ms_security.Models.Role;
import com.sgm.ms_security.Repositories.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@CrossOrigin
@RestController
@RequestMapping("/roles")
public class RolesController {

    @Autowired
    private RoleRepository theRoleRepository;

    @GetMapping("")
    public List<Role> findAll() {
        return this.theRoleRepository.findAll();
    }


    @GetMapping("/mas-veces/{roleId}")
    public ResponseEntity<String> getMostUsedMethod(@PathVariable String roleId) {
        Optional<Role> roleOpt = theRoleRepository.findById(roleId);
        if (roleOpt.isPresent()) {
            String mostUsedMethod = roleOpt.get().getMostUsedMethod();
            return ResponseEntity.ok(mostUsedMethod);
        }
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Role not found");
    }

    @GetMapping("{id}")
    public Role findById(@PathVariable String id) {
        return this.theRoleRepository.findById(id).orElse(null);
    }

    @PostMapping
    public Role create(@RequestBody Role newRole) {
        return this.theRoleRepository.save(newRole);
    }

    @PutMapping("{id}")
    public Role update(@PathVariable String id, @RequestBody Role newRole) {
        Role actualRole = this.theRoleRepository.findById(id).orElse(null);
        if (actualRole != null) {
            actualRole.setName(newRole.getName());
            actualRole.setDescription(newRole.getDescription());
            return this.theRoleRepository.save(actualRole);
        }
        return null;
    }

    @DeleteMapping("{id}")
    public void delete(@PathVariable String id) {
        Role theRole = this.theRoleRepository.findById(id).orElse(null);
        if (theRole != null) {
            this.theRoleRepository.delete(theRole);
        }
    }
}
