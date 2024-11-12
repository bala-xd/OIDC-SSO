package com.user.repo;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.user.model.User;

@Repository
public interface IUserRepository extends JpaRepository<User, UUID> {
	
	public User findByUsername(String username);
	
	public User findByEmail(String email);
	
	Optional<User> findByUsernameOrEmail(String username, String email);
}
