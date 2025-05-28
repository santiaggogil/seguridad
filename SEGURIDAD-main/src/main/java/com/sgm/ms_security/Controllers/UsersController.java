package com.sgm.ms_security.Controllers;

import com.sgm.ms_security.Models.User;
import com.sgm.ms_security.Repositories.UserRepository;
import com.sgm.ms_security.Services.EncryptionService;
import com.sgm.ms_security.Services.RequestURL;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin
@RestController
@RequestMapping("/api/users")
public class UsersController {
    @Autowired
    private UserRepository theUserRepository;

    @Autowired
    private EncryptionService theEncryptionService;

    @Autowired
    private RequestURL requestURL;

    @GetMapping("")
    public List<User> find(){
        return this.theUserRepository.findAll();
    }

    @GetMapping("{id}")
    public User findById(@PathVariable String id){
        User theUser=this.theUserRepository.findById(id).orElse(null);
        return theUser;
    }

    @PostMapping
    public User create(@RequestBody User newUser) {
        if (this.theUserRepository.getUserByEmail(newUser.getEmail()) == null) {
            newUser.setPassword(theEncryptionService.convertSHA256(newUser.getPassword()));
            return this.theUserRepository.save(newUser);
        }else {
            return null;
        }
    }

    @PutMapping("{id}")
    public User update(@PathVariable String id, @RequestBody User newUser){
        User actualUser=this.theUserRepository.findById(id).orElse(null);
        if(actualUser!=null){
            actualUser.setName(newUser.getName());
            actualUser.setEmail(newUser.getEmail());
            actualUser.setPassword(newUser.getPassword());
            this.theUserRepository.save(actualUser);
            return actualUser;
        }else{
            return null;
        }
    }
    @DeleteMapping("{id}")
    public void delete(@PathVariable String id){
        User theUser=this.theUserRepository.findById(id).orElse(null);
        if (theUser!=null){
            this.theUserRepository.delete(theUser);
        }
    }
}
