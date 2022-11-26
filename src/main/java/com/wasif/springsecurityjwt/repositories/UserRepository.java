package com.wasif.springsecurityjwt.repositories;

import com.wasif.springsecurityjwt.entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<AppUser, Long> {
    AppUser findByUserName(String username);
}
