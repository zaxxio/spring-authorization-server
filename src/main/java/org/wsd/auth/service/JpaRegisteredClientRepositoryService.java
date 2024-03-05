package org.wsd.auth.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.wsd.auth.domain.ClientEntity;
import org.wsd.auth.repository.ClientRepository;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Service
public class JpaRegisteredClientRepositoryService implements RegisteredClientRepository {
    private final ClientRepository clientRepository;
    private ObjectMapper objectMapper = new ObjectMapper();

    public JpaRegisteredClientRepositoryService(ClientRepository clientRepository) {
        this.clientRepository = clientRepository;
        ClassLoader classLoader = JpaRegisteredClientRepositoryService.class.getClassLoader();
        final List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
        this.objectMapper.registerModules(securityModules);
        this.objectMapper.registerModules(new OAuth2AuthorizationServerJackson2Module());
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        if (registeredClient == null) {
            throw new RuntimeException("Registered Client can not be null.");
        }
        this.clientRepository.save(convertToClientEntity(registeredClient));
    }

    private ClientEntity convertToClientEntity(RegisteredClient registeredClient) {
        List<String> clientAuthenticationMethods = new ArrayList<>(registeredClient.getClientAuthenticationMethods().size());
        registeredClient.getClientAuthenticationMethods().forEach(authenticationMethod -> clientAuthenticationMethods.add(authenticationMethod.getValue()));

        List<String> authorizationGrantTypes = new ArrayList<>(registeredClient.getAuthorizationGrantTypes().size());
        registeredClient.getAuthorizationGrantTypes().forEach(grantType -> authorizationGrantTypes.add(grantType.getValue()));

        ClientEntity client = new ClientEntity();
        client.setId(registeredClient.getId());
        client.setClientId(registeredClient.getClientId());
        client.setClientName(registeredClient.getClientName());
        client.setClientIdIssuedAt(registeredClient.getClientIdIssuedAt());
        client.setClientSecretExpiresAt(registeredClient.getClientSecretExpiresAt());
        client.setClientSecret(registeredClient.getClientSecret());
        client.setClientAuthenticationMethods(StringUtils.collectionToCommaDelimitedString(clientAuthenticationMethods));
        client.setAuthorizationGrantTypes(StringUtils.collectionToCommaDelimitedString(authorizationGrantTypes));
        client.setRedirectUris(StringUtils.collectionToCommaDelimitedString(registeredClient.getRedirectUris()));
        client.setScopes(StringUtils.collectionToCommaDelimitedString(registeredClient.getScopes()));
        client.setClientSettings(convertMapToString(registeredClient.getClientSettings().getSettings()));
        client.setTokenSettings(convertMapToString(registeredClient.getTokenSettings().getSettings()));
        return client;
    }

    private String convertMapToString(Map<String, Object> settings) {
        try {
            return this.objectMapper.writeValueAsString(settings);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public RegisteredClient findById(String id) {
        return this.clientRepository.findById(id).map(this::convertEntityToRegisterClient).orElseThrow(() -> new RuntimeException("RegisterClient Id not found."));
    }

    private RegisteredClient convertEntityToRegisterClient(ClientEntity clientEntity) {
        if (clientEntity.getClientSecretExpiresAt() != null && clientEntity.getClientSecretExpiresAt().isBefore(Instant.now())) {
            throw new IllegalStateException("The client secret has expired. Please renew your client credentials.");
        }
        Set<String> authorizationGrantTypes = StringUtils.commaDelimitedListToSet(clientEntity.getAuthorizationGrantTypes());
        Set<String> clientAuthenticationMethods = StringUtils.commaDelimitedListToSet(clientEntity.getClientAuthenticationMethods());
        Set<String> clientRedirectUris = StringUtils.commaDelimitedListToSet(clientEntity.getRedirectUris());
        Set<String> clientScopes = StringUtils.commaDelimitedListToSet(clientEntity.getScopes());

        RegisteredClient.Builder builder = RegisteredClient.withId(clientEntity.getId())
                .clientId(clientEntity.getClientId())
                .clientName(clientEntity.getClientName())
                .clientIdIssuedAt(clientEntity.getClientIdIssuedAt())
                .clientSecretExpiresAt(clientEntity.getClientSecretExpiresAt())
                .clientSecret(clientEntity.getClientSecret())
                .redirectUris((uris) -> uris.addAll(clientRedirectUris))
                .scopes((sc) -> sc.addAll(clientScopes))
                .clientAuthenticationMethods(
                        authenticationMethods -> {
                            clientAuthenticationMethods.forEach(
                                    method -> {
                                        authenticationMethods.add(resolveClientAuthenticationMethod(method));
                                    }
                            );
                        }
                ).authorizationGrantTypes(
                        grantTypes -> {
                            authorizationGrantTypes.forEach(
                                    type -> {
                                        grantTypes.add(resolveAuthorizationGrantType(type));
                                    }
                            );
                        }
                );

        builder.clientSettings(ClientSettings.withSettings(parseMapFromString(clientEntity.getClientSettings())).build());
        builder.tokenSettings(TokenSettings.withSettings(parseMapFromString(clientEntity.getTokenSettings())).build());

        return builder.build();
    }

    private Map<String, Object> parseMapFromString(String clientSettings) {
        try {
            return this.objectMapper.readValue(clientSettings, new TypeReference<>() {
            });
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
    }

    private AuthorizationGrantType resolveAuthorizationGrantType(String authorizationGrantType) {
        if (AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.AUTHORIZATION_CODE;
        } else if (AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.CLIENT_CREDENTIALS;
        } else if (AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.REFRESH_TOKEN;
        }
        return new AuthorizationGrantType(authorizationGrantType);
    }

    private ClientAuthenticationMethod resolveClientAuthenticationMethod(String clientAuthenticationMethod) {
        if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue().equals(clientAuthenticationMethod)) {
            return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
        } else if (ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue().equals(clientAuthenticationMethod)) {
            return ClientAuthenticationMethod.CLIENT_SECRET_POST;
        } else if (ClientAuthenticationMethod.NONE.getValue().equals(clientAuthenticationMethod)) {
            return ClientAuthenticationMethod.NONE;
        }
        return new ClientAuthenticationMethod(clientAuthenticationMethod);      // Custom client authentication method;
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return this.clientRepository.findByClientId(clientId).map(this::convertEntityToRegisterClient).orElse(null);
    }
}
