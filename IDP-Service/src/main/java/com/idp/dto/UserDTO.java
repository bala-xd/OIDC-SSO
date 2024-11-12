package com.idp.dto;

import java.util.Set;
import java.util.UUID;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserDTO {

    private UUID id;

	private String email;
    private String username;
	private String password;
	
	private Set<String> roles;
	
//	private String name;
//	private String address;
//	private String email;
//	private String phone;
}
