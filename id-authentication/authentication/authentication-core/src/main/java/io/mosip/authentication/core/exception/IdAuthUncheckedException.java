package io.mosip.authentication.core.exception;

import io.mosip.authentication.core.constant.IdAuthenticationErrorConstants;
import io.mosip.kernel.core.exception.BaseUncheckedException;

/**
 * @author Arun Bose
 * 
 * The Class IdAuthUncheckedException to handle unchecked exceptions
 */
public class IdAuthUncheckedException extends BaseUncheckedException {

	
	private static final long serialVersionUID = 8889706680648642483L;


	/**
	 * Instantiates a new id auth unchecked exception.
	 */
	public IdAuthUncheckedException() {
		super();
	}

	/**
	 * Instantiates a new id repo app unchecked exception.
	 *
	 * @param errorCode    the error code
	 * @param errorMessage the error message
	 */
	public IdAuthUncheckedException(String errorCode, String errorMessage) {
		super(errorCode, errorMessage);
	}

	/**
	 * Instantiates a new id repo app unchecked exception.
	 *
	 * @param errorCode    the error code
	 * @param errorMessage the error message
	 * @param rootCause    the root cause
	 */
	public IdAuthUncheckedException(String errorCode, String errorMessage, Throwable rootCause) {
		super(errorCode, errorMessage, rootCause);
	}

	
	/**
	 * Instantiates a new id repo app unchecked exception.
	 *
	 * @param exceptionConstant the exception constant
	 */
	public IdAuthUncheckedException(IdAuthenticationErrorConstants exceptionConstant) {
		this(exceptionConstant.getErrorCode(), exceptionConstant.getErrorMessage());
	}
	
	public IdAuthUncheckedException(IdAuthenticationErrorConstants exceptionConstant, Throwable rootCause) {
		this(exceptionConstant.getErrorCode(), exceptionConstant.getErrorMessage(), rootCause);
	}
}
