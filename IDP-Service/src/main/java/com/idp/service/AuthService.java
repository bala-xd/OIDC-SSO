package com.idp.service;

import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Service;

import com.idp.dto.LoginDTO;
import com.idp.dto.UserDTO;
import com.idp.proxy.IUserProxy;

@Service
public class AuthService {
	
	/*@Autowired
	IUserProxy userProxy;
	
	@Autowired
	JwtService jwtService;
	
	@Autowired
	AuthenticationManager authManager;
	
	private static final Pattern EMAIL_PATTERN = Pattern.compile("^[\\w.%+-]+@[\\w.-]+\\.[a-zA-Z]{2,}$");
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_]{3,}$");

	public String verifyUser(LoginDTO cred) {
		Authentication authentication = authManager
				.authenticate(new UsernamePasswordAuthenticationToken(cred.getUsernameOrEmail(), cred.getPassword()));
		if (authentication.isAuthenticated())
			return jwtService.generateToken(userProxy.getUser(cred.getUsernameOrEmail()));
		return "fail";
	}
	
	public UserDTO registerUser(UserDTO userDTO) {
        String validationError = validateUserDTO(userDTO);
        
        if (validationError != null) {
            throw new IllegalArgumentException(validationError); // Or handle with custom exception
        }

        return userProxy.registerUser(userDTO);
    }

    private String validateUserDTO(UserDTO userDTO) {
    	if (userDTO.getUsername().length() == 0)
                return "Username can't be Empty!";
    
	    if (userDTO.getEmail().length() == 0)
	        return "Email can't be Empty!";
    	
        if (!EMAIL_PATTERN.matcher(userDTO.getUsername()).matches() &&
            !USERNAME_PATTERN.matcher(userDTO.getUsername()).matches()) {
            return "Invalid Email or Username!";
        }

        if (userDTO.getPassword().length() < 4)
            return "Password must be at least 4 characters long!";

        return null;
    }*/
	
}
