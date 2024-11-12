package com.user.service;

import java.util.HashSet;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.user.model.User;
import com.user.repo.IUserRepository;

@Service
public class UserService {
	
	@Autowired
	public IUserRepository repo;
	
	private BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(10);
	

	public User registerUser(User user) {
		Optional<User> optional = repo.findByUsernameOrEmail(user.getUsername(), user.getEmail());
		if (optional.isPresent()) 
			return null;
	    
		user.setPassword(encoder.encode(user.getPassword()));
	    
	    if (user.getRoles() == null || !user.getRoles().contains("ROLE_USER")) {
	        if (user.getRoles() == null)
	            user.setRoles(new HashSet<>());
	        user.getRoles().add("ROLE_USER");
	    }
	    
	    return repo.save(user);
	}
	
	public User validateUser(User u) {
		User user = repo.findByUsername(u.getUsername());
		if (user != null && encoder.matches(u.getPassword(), user.getPassword())) 
			return user;
		
		return null;
	}

	public User getUserByUsername(String username) {
		return repo.findByUsername(username);
	}

	public User editUser(User u) {
		User user = repo.findByEmail(u.getEmail());
		if (user==null) return null;
		u.setId(user.getId());
		return repo.save(u);
	}

	public User getUserByUsernameOrEmail(String usernameOrEmail) {
		Optional<User> op = repo.findByUsernameOrEmail(usernameOrEmail, usernameOrEmail);
		return op.isEmpty() ? null : op.get();
	}

	public User getUserByEmail(String email) {
		// TODO Auto-generated method stub
		return repo.findByEmail(email);
	}
	
}
