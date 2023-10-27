
package io.mosip.kernel.otpmanager.constant;

/**
 * This ENUM provides all the constant identified for OTP errors.
 * 
 * @author Sagar Mahapatra
 * @author Ritesh Sinha
 * @version 1.0.0
 *
 */
public enum OtpErrorConstants {
	OTP_GEN_ILLEGAL_KEY_INPUT("KER-OTG-001", "Key length should be in the range of 3-64."),
	OTP_VAL_INVALID_KEY_INPUT("KER-OTV-001", "Key can't be empty or null."),
	OTP_VAL_ILLEGAL_KEY_INPUT("KER-OTV-002", "Length of key should be in the range of 3-64."),
	OTP_VAL_INVALID_OTP_INPUT("KER-OTV-003", "OTP can't be empty or null."),
	OTP_VAL_ILLEGAL_OTP_INPUT("KER-OTV-004",
			"OTP consists of only numeric characters. No other characters is allowed."),
	OTP_VAL_KEY_NOT_FOUND("KER-OTV-005", "Validation can't be performed against this key. Generate OTP first."),
	INTERNAL_SERVER_ERROR("KER-OTV-500", "Internal server error"),
	HTTP_MESSAGE_NOT_READABLE("KER-OTV-999", "HTTP Message Not Readable Exception"),
	OTP_GEN_CRYPTO_FAILURE("KER-OTG-002", "Crypto failure"),
	OTP_GEN_ALGO_FAILURE("KER-OTG-003", "Invalid key or algorithm found"),
	OTP_GEN_IO_FAILURE("KER-OTG-004", "IO exception found");

	/**
	 * The error code.
	 */
	private final String errorCode;

	/**
	 * The error message.
	 */
	private final String errorMessage;

	/**
	 * @param errorCode    The error code to be set.
	 * @param errorMessage The error message to be set.
	 */
	private OtpErrorConstants(String errorCode, String errorMessage) {
		this.errorCode = errorCode;
		this.errorMessage = errorMessage;
	}

	/**
	 * @return The error code.
	 */
	public String getErrorCode() {
		return errorCode;
	}

	/**
	 * @return The error message.
	 */
	public String getErrorMessage() {
		return errorMessage;
	}
}
