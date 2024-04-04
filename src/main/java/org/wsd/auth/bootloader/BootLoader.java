package org.wsd.auth.bootloader;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.AdviceMode;
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
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.transaction.annotation.Transactional;
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
@EnableTransactionManagement
public class BootLoader implements CommandLineRunner {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JpaRegisteredClientRepositoryService jpaRegisteredClientRepositoryService;

    @Override
    @Transactional
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
                .scope("read")
                .clientIdIssuedAt(Instant.now())
                .clientSecretExpiresAt(Instant.now().plus(365, ChronoUnit.DAYS))
                .redirectUri("https://oidcdebugger.com/debug")
                .redirectUri("http://localhost:8080/swagger-ui/oauth2-redirect.html")
                .redirectUri("https://oauthdebugger.com/debug")
                .redirectUri("https://springone.io/authorized")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .clientSettings(clientSettings())
                .tokenSettings(tokenSettings())
                .build();

        this.jpaRegisteredClientRepositoryService.save(oidcClient);
    }

    @Bean
    public ClientSettings clientSettings() {
        return ClientSettings.builder()
                .requireProofKey(true)
                .requireAuthorizationConsent(true)
                .build();
    }


    @Bean
    public TokenSettings tokenSettings() {
        return TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofMinutes(60))
                .build();
    }
}
