package io.mosip.registration.processor.packet.receiver.dto;

import lombok.Data;

/**
 * The Class ErrorDto.
 *
 * @author Girish Yarru
 */
@Data
public class ErrorDto {
	
	/** The error code. */
	private String errorCode;
	
	/** The error message. */
	private String errorMessage;

}
