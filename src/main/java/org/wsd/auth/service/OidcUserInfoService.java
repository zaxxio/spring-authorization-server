package org.wsd.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.wsd.auth.domain.UserEntity;
import org.wsd.auth.repository.UserRepository;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class OidcUserInfoService {
    private final UserRepository userRepository;

    public OidcUserInfo loadUser(String username) {
        OidcUserInfo oidcUserInfo = null;
        Optional<UserEntity> entity = userRepository.findUserEntityByUsername(username);
        if (entity.isPresent()) {
            oidcUserInfo = OidcUserInfo.builder()
                    .subject(username)
                    .name(entity.get().getUsername())
                    .givenName("First")
                    .familyName("Last")
                    .middleName("Middle")
                    .nickname("User")
                    .preferredUsername(username)
                    .profile("https://example.com/" + username)
                    .picture("https://example.com/" + username + ".jpg")
                    .website("https://example.com")
                    .email(username + "@example.com")
                    .emailVerified(true)
                    .gender("female")
                    .birthdate("2023-01-01")
                    .zoneinfo("Europe/Brussels")
                    .locale("en-US")
                    .phoneNumber("+1 (604) 555-1234;ext=5678")
                    .phoneNumberVerified(false)
                    .claim("address", "Champ de Mars 5 Av. Anatole France 75007 Paris France")
                    .updatedAt("2023-01-01T00:00:00Z")
                    .build();
        }
        return oidcUserInfo;
    }
}
