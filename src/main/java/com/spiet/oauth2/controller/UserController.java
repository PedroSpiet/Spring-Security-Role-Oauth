package com.spiet.oauth2.controller;

import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import com.spiet.oauth2.common.Constants;
import com.spiet.oauth2.models.User;
import com.spiet.oauth2.repository.UserRepository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.method.P;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/user")
public class UserController {
    

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;


    @PostMapping(path = "/join")
    public String joinGroup(@RequestBody User user) {
        user.setRole(Constants.DEFAULT_ROLE);
        String encryptedPwd = passwordEncoder.encode(user.getPassword());
        user.setPassword(encryptedPwd);
        userRepository.save(user); 
        return "HI " + user.getUserName() + " Welcome to group!";
    }

    @GetMapping
    @Secured("ROLE_ADMIN")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public List<User> loadUsers() {
        return userRepository.findAll();
    }

    @GetMapping("/test")
    @Secured("ROLE_USER")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public String testUserAccess() {
        return "user can only Access this";
    }

    @GetMapping("/access/{userId}/{userRole}")
    //@Secured("ROLE_ADMIN")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') or hasAuthority('ROLE_MODERATOR')")
    public String giveAccessToUser(@PathVariable Long userId, 
                                    @PathVariable String userRole, Principal principal) {

        var user = userRepository.findById(userId).get();
        List<String> activeRoles = getRolesByLoggedInUser(principal);

        String newRole = "";

        if(activeRoles.contains(userRole)) {
            newRole = user.getRole() + "," + userRole;
            user.setRole(newRole);
            userRepository.save(user);
        }

        return "Hi " + user.getUserName() + " New Role assign to you by " + principal.getName();
    }

    private List<String> getRolesByLoggedInUser(Principal principal) {
        var roles = getLoggedInUser(principal).getRole();
        List<String> assignRoles = Arrays.stream(roles.split(",")).collect(Collectors.toList());
        
        if(assignRoles.contains("ROLE_ADMIN")) {
            return Arrays.stream(Constants.ADMIN_ACCESS).collect(Collectors.toList());
        }

        if(assignRoles.contains("ROLE_MODERATOR")) {
            return Arrays.stream(Constants.MODERATOR_ACCESS).collect(Collectors.toList());
        }
        
        return Collections.emptyList();
    }

    private User getLoggedInUser(Principal principal) {
        return userRepository.findByUserName(principal.getName()).get();
    }
}
