package com.sgm.ms_security.Repositories;

import com.sgm.ms_security.Models.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

public interface UserRepository extends MongoRepository<User, String> {

    @Query("{'email': ?0}") // el ?0, significa que es la posicion del parametro que entra abajo
    public User getUserByEmail(String email); //

}
