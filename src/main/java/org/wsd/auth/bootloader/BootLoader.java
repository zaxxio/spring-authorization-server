package org.wsd.auth.bootloader;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.wsd.auth.domain.RoleEntity;
import org.wsd.auth.domain.UserEntity;
import org.wsd.auth.repository.UserRepository;

import java.util.Set;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class BootLoader implements CommandLineRunner {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    @Override
    public void run(String... args) throws Exception {
        final UserEntity user = new UserEntity();
        user.setUserId(UUID.randomUUID());
        user.setUsername("user");
        user.setPassword(passwordEncoder.encode("123456"));

        final RoleEntity role = new RoleEntity();
        role.setName("USER");
        user.setRoleEntities(Set.of(role));
        userRepository.save(user);
    }
}
