package com.security.authapi.repository;

import com.security.authapi.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<UserDetails> findUserByEmail(String username);
}
