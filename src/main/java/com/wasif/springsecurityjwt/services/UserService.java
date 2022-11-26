package com.wasif.springsecurityjwt.services;

import com.wasif.springsecurityjwt.entities.AppUser;
import com.wasif.springsecurityjwt.entities.Role;

import java.util.List;

public interface UserService {
    AppUser saveUser(AppUser user);

    Role saveRole(Role role);

    void addRoleToUser(String username, String roleName);

    AppUser getUser(String username);

    List<AppUser> getUsers();
}
