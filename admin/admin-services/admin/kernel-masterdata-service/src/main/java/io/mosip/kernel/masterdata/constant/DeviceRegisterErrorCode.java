package io.mosip.kernel.masterdata.constant;

/**
 * Constants for Device History Details
 * 
 * @author Srinivasan
 * @since 1.0.0
 *
 */
public enum DeviceRegisterErrorCode {
	DEVICE_REGISTER_FETCH_EXCEPTION("ADM-DPM-056", "Error occured while fetching Device Register details"),
	INVALID_STATUS_CODE("ADM-DPM-037", "Invalid status received"),
	DEVICE_REGISTER_UPDATE_EXCEPTION("ADM-DPM-057", "Error occured while updating Device Register details"),
	DEVICE_REGISTER_CREATE_EXCEPTION("ADM-DPM-058", "Error occured while create Device Register details"),
	DEVICE_REGISTER_DELETED_EXCEPTION("ADM-DPM-050", "Error occured while deleted Device Register details"),
	DATA_NOT_FOUND_EXCEPTION("ADM-DPM-038", "Data not found for provided device code"),
	DATA_NOT_FOUND_DEVICE_REGISTER("ADM-DPM-038", "Data not found for provided device code"),
	DEVICE_DE_REGISTERED_ALREADY("KER-DPR-002", "Device already de-registered"),
	DEVICE_REGISTER_NOT_FOUND_EXCEPTION("KER-DPR-001", "No register device found"),
	INVALID_DEVICE_CODE_LENGTH("KER-DPR-003", "Device code length exceeds the accepted limit"),
	INVALID_ENVIRONMENT("KER-DPR-004", "Invalid environment"),
	DEVICE_REGISTERED_STATUS_ALREADY("KER-DPM-039", "Device already is in %s status"),
	DEVICE_REVOKED("ADM-DPM-059", "Device has been revoked");

	private final String errorCode;
	private final String errorMessage;

	private DeviceRegisterErrorCode(final String errorCode, final String errorMessage) {
		this.errorCode = errorCode;
		this.errorMessage = errorMessage;
	}

	public String getErrorCode() {
		return errorCode;
	}

	public String getErrorMessage() {
		return errorMessage;
	}

}
