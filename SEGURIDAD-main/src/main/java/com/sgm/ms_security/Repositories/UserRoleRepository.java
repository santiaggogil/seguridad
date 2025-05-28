package com.sgm.ms_security.Repositories;

import com.sgm.ms_security.Models.User;
import com.sgm.ms_security.Models.UserRole;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

import java.util.List;
import java.util.Optional;

public interface UserRoleRepository extends MongoRepository<UserRole, String> {
    @Query("{ 'user.$id' : ObjectId(?0) }")
    public List<UserRole> getRolesByUserId(String userId);

    @Query("{ 'role.$id' : ObjectId(?0) }")
    List<UserRole> getUsersByRoleId(String roleId);

    Optional<UserRole> findByUserId(String id); // Buscar UserRole por el ID del usu

}
