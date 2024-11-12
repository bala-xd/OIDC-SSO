package com.idp.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.idp.dto.UserDTO;
import com.idp.dto.UserPrincipal;
import com.idp.proxy.IUserProxy;

@Service
public class CustomUserDetailsService implements UserDetailsService {
	
	@Autowired
	IUserProxy userProxy;

	/*@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		UserDTO uDto = userProxy.getUser(username);
		if (uDto == null)
			throw new UsernameNotFoundException("User not found with username: " + username);
		return new UserPrincipal(uDto);
	}*/
	
	@Override
    public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
        UserDTO uDto = userProxy.getUser(usernameOrEmail);
        if (uDto == null)
        	throw new UsernameNotFoundException("User not found!");
        return new UserPrincipal(uDto); // CustomUserDetails implements UserDetails
    }

}
