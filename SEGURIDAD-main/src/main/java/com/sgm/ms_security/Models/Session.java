package com.sgm.ms_security.Models;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Date;

@Setter
@Getter
@Data
@Document
public class Session {

    @Id
    private String _id;
    private String token;
    private Date expirationDate;
    private String validationCode;
    private int timesErrorValidationCode;
    @DBRef
    private User user; // This is the user that is logged in

    public Session() {
    }

    public String get_id() {
        return _id;
    }

    public void set_id(String _id) {
        this._id = _id;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public Date getExpirationDate() {
        return expirationDate;
    }

    public void setExpirationDate(Date expirationDate) {
        this.expirationDate = expirationDate;
    }

    public String getValidationCode() {
        return validationCode;
    }

    public void setValidationCode(String validationCode) {
        this.validationCode = validationCode;
    }

    public int getTimesErrorValidationCode() {
        return timesErrorValidationCode;
    }

    public void setTimesErrorValidationCode(int timesErrorValidationCode) {
        this.timesErrorValidationCode = timesErrorValidationCode;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }
}