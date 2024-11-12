package com.idp.service;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.stereotype.Service;

import com.idp.dto.UserDTO;
import com.idp.proxy.IUserProxy;

@Service
public class OidcUserInfoService {

	private final UserInfoRepository userInfoRepository;

	@Autowired
	public OidcUserInfoService(UserInfoRepository userInfoRepository) {
		this.userInfoRepository = userInfoRepository;
	}

	public OidcUserInfo loadUser(String username) {
		return new OidcUserInfo(this.userInfoRepository.findByUsername(username));
	}
}

@Service
class UserInfoRepository {
	
	@Autowired
	private IUserProxy userProxy;
	
	private final Map<String, Map<String, Object>> userInfo = new HashMap<>();
	
	@jakarta.annotation.PostConstruct
	public void initialize() {
		initializeUser("bala");
	}

	private void initializeUser(String username) {
		UserDTO userDTO = userProxy.getUser(username);
		if (userDTO != null) {
			this.userInfo.put(username, createUser(username, userDTO));
		}
	}

	public Map<String, Object> findByUsername(String username) {
		return this.userInfo.getOrDefault(username, Collections.emptyMap());
	}

	private Map<String, Object> createUser(String username, UserDTO userDTO) {
		return OidcUserInfo.builder()
				.subject(username)
				.email(userDTO.getEmail())
				.emailVerified(true)
				.build()
				.getClaims();
	}
}
