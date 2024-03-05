package org.wsd.auth.bootloader;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;
import org.wsd.auth.domain.RoleEntity;
import org.wsd.auth.domain.UserEntity;
import org.wsd.auth.repository.UserRepository;
import org.wsd.auth.service.JpaRegisteredClientRepositoryService;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class BootLoader implements CommandLineRunner {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JpaRegisteredClientRepositoryService jpaRegisteredClientRepositoryService;

    @Override
    public void run(String... args) throws Exception {
        final UserEntity user = new UserEntity();
        user.setUserId(UUID.randomUUID());
        user.setUsername("user");
        user.setPassword(passwordEncoder.encode("password"));

        final RoleEntity role = new RoleEntity();
        role.setName("USER");
        user.setRoleEntities(Set.of(role));
        userRepository.save(user);

        final RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client")
                .clientSecret(passwordEncoder.encode("secret"))
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .clientIdIssuedAt(Instant.now())
                .clientSecretExpiresAt(Instant.now().plus(365, ChronoUnit.DAYS))
                .redirectUri("https://oidcdebugger.com/debug")
                .redirectUri("https://oauthdebugger.com/debug")
                .redirectUri("https://springone.io/authorized")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .clientSettings(clientSettings())
                .tokenSettings(tokenSettings())
                .build();

        this.jpaRegisteredClientRepositoryService.save(oidcClient);
    }

    public ClientSettings clientSettings() {
        return ClientSettings.builder()
                .requireProofKey(true)
                .build();
    }

    public TokenSettings tokenSettings() {
        return TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                .accessTokenTimeToLive(Duration.ofDays(7))
                .build();
    }
}
