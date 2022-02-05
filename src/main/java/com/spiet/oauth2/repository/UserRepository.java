package com.spiet.oauth2.repository;

import java.util.Optional;

import com.spiet.oauth2.models.User;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Long>{
    Optional<User> findByUserName(String username);
}
