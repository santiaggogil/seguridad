package com.sgm.ms_security.Repositories;

import com.sgm.ms_security.Models.Role;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

import java.util.Optional;

public interface RoleRepository extends MongoRepository<Role, String> {
}