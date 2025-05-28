package com.sgm.ms_security.Models;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;


@Data //para que guarde esa clase en persistencia, se almacena en una base de datos
@Document //de mongo, como quiere lo que se llame la tabla en la base de datos, toma el nombre por defecto del usuario
public class User {
    @Id //a mongo, para decirle que el atributo Id se cree automaticamente
    private String _id;
    private String name;

    public String get_id() {
        return _id;
    }

    public void set_id(String _id) {
        this._id = _id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    private String email;
    private String password;


    public User() {
        this.name = name;
        this.email = email;
        this.password = password;
    }

    public String getId() {
        return _id;
    }
}