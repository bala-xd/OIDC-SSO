package com.idp.dto;

import java.io.Serial;
import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.idp.proxy.IUserProxy;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class UserPrincipal implements UserDetails {

	@Serial
	private static final long serialVersionUID = 1L;
	
	private final UserDTO uDTO;
	
	@Autowired
	IUserProxy userProxy;

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		Set<String> roles = uDTO.getRoles();
		return roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
	}

	@Override
	public String getPassword() {
		return uDTO.getPassword();
	}

	@Override
	public String getUsername() {
		return uDTO.getUsername();
	}
	
	public String getEmail() {
		return uDTO.getEmail();
	}
}
