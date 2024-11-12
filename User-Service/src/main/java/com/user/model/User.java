package com.user.model;

import java.util.Set;
import java.util.UUID;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Entity
@Table(name="users_table")
@NoArgsConstructor
@AllArgsConstructor
public class User {
	@Id
	@GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
	
	private String email;
	private String username;
	private String password;
	
	private Set<String> roles;
	
//	private String name;
//	private String phone;
	
}
