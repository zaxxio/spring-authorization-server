package org.wsd.auth.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.CacheConcurrencyStrategy;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.io.Serializable;
import java.time.Instant;

import static jakarta.persistence.TemporalType.TIMESTAMP;

@Getter
@Setter
@ToString
@MappedSuperclass
@RequiredArgsConstructor
@EntityListeners(AuditingEntityListener.class)
@Cacheable
@org.hibernate.annotations.Cache(usage = CacheConcurrencyStrategy.READ_WRITE)
public abstract class AbstractAuditableEntity implements Serializable {

    @CreatedBy
    @Column(name = "created_by", nullable = false, length = 50, updatable = false)
    @JsonIgnore
    protected String createdBy;

    @CreatedDate
    @Temporal(TIMESTAMP)
    @Column(name = "created_date", updatable = false)
    @JsonIgnore
    protected Instant createdDate = Instant.now();

    @LastModifiedBy
    @Column(name = "last_modified_by", length = 50)
    @JsonIgnore
    protected String lastModifiedBy;

    @LastModifiedDate
    @Temporal(TIMESTAMP)
    @Column(name = "last_modified_date")
    @JsonIgnore
    private Instant lastModifiedDate = Instant.now();

    @JsonIgnore
    protected String lastModifiedIp;

    @PrePersist
    @PreUpdate
    public void updateLastModifiedIp() {
        // Note: this is a simplification. You'd need a reliable way to access the current request's
        // IP address, which could be stored in a ThreadLocal or some other context holder.
        ServletRequestAttributes sra = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();

        // Check if the attributes are present and are of the correct type.
        if (sra != null) {
            HttpServletRequest request = sra.getRequest();
            // Check if the request is available.
            if (request != null) {
                // Safe extraction of the client IP address.
                this.lastModifiedIp = request.getRemoteAddr();
            } else {
                // Handle the case where there's no request available.
                // This can depend on your requirements or use case.
                this.lastModifiedIp = "N/A"; // or any other appropriate default value
            }
        } else {
            // Handle the situation where the code wasn't executed within the HTTP request-response cycle.
            this.lastModifiedIp = "N/A"; // or any other appropriate default value
        }
    }

}