package io.mosip.kernel.idvalidator.rid.constant;

/**
 * This enum contains all exception properties that are required to validate
 * RID.
 * 
 * @author Ritesh Sinha
 * @since 1.0.0
 *
 */
public enum RidExceptionProperty {
	INVALID_RID("KER-IDV-301", "Rid Must Be Numeric Only"), INVALID_CENTER_ID("KER-IDV-302", "Center Id Did Not Match"),
	INVALID_MACHINE_ID("KER-IDV-303", "Machine Id Did Not Match"),
	INVALID_RID_LENGTH("KER-IDV-304", "Rid Length Must Be "),
	INVALID_RID_TIMESTAMP("KER-IDV-305", "Invalid Time Stamp Found"),
	INVALID_RID_SEQ_LENGTH("KER-IDV-307", "Invalid sequence Found"),
	INVALID_RIDLENGTH_OR_CENTERIDLENGTH_MACHINEIDLENGTH_TIMESTAMPLENGTH("KER-IDV-306",
			"Rid length or center id length or machine id length or sequence length or timestamp length should not be less than or equals to zero");

	/**
	 * the errorCode.
	 */
	private String errorCode;
	/**
	 * the errorMessage.
	 */
	private String errorMessage;

	/**
	 * Constructor of RidExceptionProperty.
	 * 
	 * @param errorCode    the errorCode.
	 * @param errorMessage the errorMessage.
	 */
	RidExceptionProperty(String errorCode, String errorMessage) {
		this.errorCode = errorCode;
		this.errorMessage = errorMessage;
	}

	/**
	 * Getter for errorCode
	 * 
	 * @return the errorCode.
	 */
	public String getErrorCode() {
		return errorCode;
	}

	/**
	 * Getter for errorMessage
	 * 
	 * @return the errorMessage.
	 */
	public String getErrorMessage() {
		return errorMessage;
	}

}
