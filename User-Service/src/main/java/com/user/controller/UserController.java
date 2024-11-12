package com.user.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.user.model.User;
import com.user.service.UserService;

@RestController
@RequestMapping("/user-api")
public class UserController {
	
	@Autowired
	public UserService service;
	
	@GetMapping("")
	public String test() {
		return "User-Service API";
	}
	
	@PostMapping("/register")
	public User register(@RequestBody User u) {
		return service.registerUser(u);
	}
	
	@PostMapping("/verify")
	public User validate(@RequestBody User u) {
		return service.validateUser(u);
	}
	
	@PutMapping("/update")
	public User updateUser(@RequestBody User u) {
		return service.editUser(u);
	}
	
	@GetMapping("/user/{usernameOrEmail}")
	public User getUser(@PathVariable String usernameOrEmail) {
		return service.getUserByUsernameOrEmail(usernameOrEmail);
	}
	
}
