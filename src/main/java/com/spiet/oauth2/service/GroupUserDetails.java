package com.spiet.oauth2.service;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import com.spiet.oauth2.models.User;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import lombok.NoArgsConstructor;


@Service
@NoArgsConstructor
public class GroupUserDetails implements UserDetails{
    private String userName;
    private String password;
    private boolean isActive;
    private List<GrantedAuthority> authorities;

    public GroupUserDetails(User user) {
        this.userName = user.getUserName();
        this.password = user.getPassword();
        this.isActive = user.getActive();
        this.authorities = Arrays.stream(user.getRole().split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return userName;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}