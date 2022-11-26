package com.wasif.springsecurityjwt;

import com.wasif.springsecurityjwt.services.UserService;
import com.wasif.springsecurityjwt.entities.Role;
import com.wasif.springsecurityjwt.entities.AppUser;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class SpringSecurityJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityJwtApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner run(UserService userService){
		return args -> {
			userService.saveRole(new Role(null, "ROLE_USER"));
			userService.saveRole(new Role(null, "ROLE_MANAGER"));
			userService.saveRole(new Role(null, "ROLE_ADMIN"));
			userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

			userService.saveUser(new AppUser(null, "wasif", "wasif","12345", new ArrayList<>()));
			userService.saveUser(new AppUser(null, "altaf", "altaf","12345", new ArrayList<>()));
			userService.saveUser(new AppUser(null, "sakir", "sakir","12345", new ArrayList<>()));
			userService.saveUser(new AppUser(null, "priyatosh", "priyatosh","12345", new ArrayList<>()));

			userService.addRoleToUser("wasif","ROLE_USER");
			userService.addRoleToUser("wasif","ROLE_MANAGER");
			userService.addRoleToUser("altaf","ROLE_MANAGER");
			userService.addRoleToUser("sakir","ROLE_ADMIN");
			userService.addRoleToUser("priyatosh","ROLE_SUPER_ADMIN");
			userService.addRoleToUser("priyatosh","ROLE_ADMIN");
			userService.addRoleToUser("priyatosh","ROLE_USER");
		};
	}
}