package io.mosip.registration.processor.rest.client.audit.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
	
/**
 * Class for Audit Response having status of audit.
 *
 * @author Dharmesh Khandelwal
 * @since 1.0.0
 */

/* (non-Javadoc)
 * @see java.lang.Object#toString()
 */
@Data

/**
 * Instantiates a new audit response dto.
 */
@NoArgsConstructor

/**
 * Instantiates a new audit response dto.
 *
 * @param status the status
 */
@AllArgsConstructor
public class AuditResponseDto {

	/** The boolean audit status. */
	private boolean status;

}
