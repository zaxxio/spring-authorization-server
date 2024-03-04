package org.wsd.auth.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.Cache;
import org.hibernate.annotations.CacheConcurrencyStrategy;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.wsd.auth.domain.listener.AuditEntityListener;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "users",
        indexes = {
                @Index(name = "idx_users_username", columnList = "username"),
        })
@Builder(builderMethodName = "Builder")
@AllArgsConstructor
@EntityListeners(AuditEntityListener.class)
@JsonPropertyOrder(alphabetic = true)
@Cacheable
@Cache(usage = CacheConcurrencyStrategy.READ_WRITE)
public class UserEntity extends AbstractAuditableEntity implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID userId;
    @Column(name = "username", length = 255, unique = true, nullable = false)
    private String username;
    @JsonIgnore
    @Column(name = "password", length = 255)
    private String password;
    @CreatedBy
    private String createdBy;
    @OneToMany(targetEntity = RoleEntity.class, fetch = FetchType.EAGER, cascade = CascadeType.ALL)
    private Set<RoleEntity> roleEntities = new HashSet<>();
    private boolean accountNonExpired = true;
    private boolean accountNonLocked = true;
    private boolean credentialsNonExpired = true;
    private boolean enabled = true;
    private boolean is2FAEnabled = false;
    private String secret;

    @Override
    @JsonIgnore
    public Collection<? extends GrantedAuthority> getAuthorities() {
        final Set<GrantedAuthority> authorities = new HashSet<>();
        for (RoleEntity roleEntity : roleEntities) {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + roleEntity.getName()));
        }
        return authorities;
    }

    @Override
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

}