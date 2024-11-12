package com.idp.proxy;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

import com.idp.dto.UserDTO;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(name = "User-Service", url = "http://localhost:8001")
public interface IUserProxy {
	
	@GetMapping("user-api/user/{UsernameOrEmail}")
	UserDTO getUser(@PathVariable String UsernameOrEmail);
	
	@GetMapping("/user-api/verify")
	UserDTO verifyUser();
	
	@PostMapping("/user-api/register")
	UserDTO registerUser(@RequestBody UserDTO userDTO);
}
