package io.mosip.pms.policy.validator.exception;

import io.mosip.kernel.core.exception.BaseCheckedException;
import io.mosip.pms.policy.validator.constants.PolicyValidatorErrorConstant;

public class PolicyIOException  extends BaseCheckedException  {

	/**
	 * 
	 */
	private static final long serialVersionUID = -8957950467794649169L;

	/**
	 * Constructor for Invalid IdSchema Exception class.
	 * 
	 * @param errorCode    the error code of the exception.
	 * @param errorMessage the error message associated with the exception.
	 */
	public PolicyIOException(String errorCode, String errorMessage) {
		super(errorCode, errorMessage);
	}
	
	
	public PolicyIOException(PolicyValidatorErrorConstant errorConstant, Throwable rootCause) {
		super(errorConstant.getErrorCode(), errorConstant.getMessage(), rootCause);
	}
}
