package com.sgm.ms_security.Models;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.HashMap;
import java.util.Map;

@Data
@Document
public class Role {
    @Id
    private String _id;
    private String name;
    private String description;

    // Contador de métodos usados
    private Map<String, Integer> methodUsage = new HashMap<>();


    public Role(String name, String description) {
        this.name = name;
        this.description = description;
        this.methodUsage = new HashMap<>();
    }

    public Role() {}

    public void incrementMethodCount(String method) {
        methodUsage.put(method, methodUsage.getOrDefault(method, 0) + 1);
    }

    public String getMostUsedMethod() {
        return methodUsage.entrySet().stream()
                .max(Map.Entry.comparingByValue())
                .map(Map.Entry::getKey)
                .orElse("No data");
    }

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

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

}