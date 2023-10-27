/**
 * 
 */
package io.mosip.kernel.auditmanager.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import io.mosip.kernel.auditmanager.entity.Audit;

/**
 * Repository interface with data access and data modification functions on
 * {@link Audit}
 * 
 * @author Dharmesh Khandelwal
 * @since 1.0.0
 *
 */
public interface AuditRepository extends JpaRepository<Audit, String> {

}
