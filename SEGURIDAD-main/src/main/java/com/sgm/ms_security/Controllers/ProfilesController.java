package com.sgm.ms_security.Controllers;

import com.sgm.ms_security.Models.Profile;
import com.sgm.ms_security.Repositories.ProfileRepository;
import com.sgm.ms_security.Repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin
@RestController
@RequestMapping("/profiles")
public class ProfilesController {

    @Autowired
    private ProfileRepository theProfileRepository;

    @Autowired
    private UserRepository theUserRepository;

    @GetMapping("")
    public List<Profile> findAll() {
        return this.theProfileRepository.findAll();
    }

    @GetMapping("{id}")
    public Profile findById(@PathVariable String id) {
        return this.theProfileRepository.findById(id).orElse(null);
    }

    @PostMapping
    public Profile create(@RequestBody Profile newProfile) {
        return this.theProfileRepository.save(newProfile);
    }

    @PutMapping("{id}")
    public Profile update(@PathVariable String id, @RequestBody Profile newProfile) {
        Profile actualProfile = this.theProfileRepository.findById(id).orElse(null);
        if (actualProfile != null) {
            actualProfile.setPhone(newProfile.getPhone());
            actualProfile.setPhoto(newProfile.getPhoto());
            return this.theProfileRepository.save(actualProfile);
        }
        return null;
    }

    @DeleteMapping("{id}")
    public void delete(@PathVariable String id) {
        Profile theProfile = this.theProfileRepository.findById(id).orElse(null);
        if (theProfile != null) {
            this.theProfileRepository.delete(theProfile);
        }
    }

}
