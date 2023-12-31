package io.mosip.kernel.masterdata.constant;

/**
 * Constants for Machine Details
 * 
 * @author Megha Tanga
 * @author Ramadurai Pandian
 * @since 1.0.0
 *
 */
public enum MachineErrorCode {
	MACHINE_FETCH_EXCEPTION("KER-MSD-029", "Error occured while fetching Machines"),
	MACHINE_NOT_FOUND_EXCEPTION("KER-MSD-030", "Machine not Found"),
	MACHINE_NOT_EXIST_EXCEPTION("KER-MSD-214", "Machine ID %s does not exist"),
	MACHINE_INSERT_EXCEPTION("KER-MSD-250", "Error occurred while inserting Machine details"),
	MACHINE_UPDATE_EXCEPTION("KER-MSD-252", "Error occurred while updating Machine details"),
	MACHINE_DELETE_EXCEPTION("KER-MSD-251", "Error occurred while deleting Machine details"),
	DEPENDENCY_EXCEPTION("KER-MSD-190", "Cannot delete as dependency found"),
	REGISTRATION_CENTER_MACHINE_FETCH_EXCEPTION("KER-MSD-331",
			"Error occurred while fetching a Machine details mapped with the given Registration Center"),
	MAPPED_MACHINE_ID_NOT_FOUND_EXCEPTION("KER-MSD-326", "No assigned Machines found"),
	MACHINE_ID_ALREADY_MAPPED_EXCEPTION("KER-MSD-327", "No unassigned Machines found"),
	INVALID_MACHINE_FILTER_VALUE_EXCEPTION("KER-MSD-328", "Invalid Filter value for Mapstatus column"),
	MACHINE_ID_NOT_FOUND_FOR_NAME_EXCEPTION("KER-MSD-329", "No Machine exist for Machine Type name:%s"),
	MACHINE_SPECIFICATION_ID_NOT_FOUND_FOR_NAME_EXCEPTION("KER-MSD-330",
			"No Machine Specification found for the Machine Type name:%s"),
	MACHINE_NOT_TAGGED_TO_ZONE("KER-MSD-342", "No zone assigned to the user"),
	MACHINE_ZONE_NOT_FOUND_EXCEPTION("KER-MSD-225", "User is not authorized to decommission the machine "),
	INVALID_MACHINE_ZONE("KER-MSD-255", "Admin not authorized to access this Machine for this Zone"),
	ZONE_NOT_EXIST("KER-MSD-343", "Zone %s doesn't exist"),
	MACHINE_ID("KER-MSD-437", "Machine ID %s does not exist for primary language"),
	MAPPED_TO_REGCENTER("KER-MSD-256", "Machine cannot Decommissioned as some Registration centers are mapped"), 
	INVALID_PUBLIC_KEY("KER-MSD-257", "Invalid public key provided"),
	INVALID_SIGN_PUBLIC_KEY("KER-MSD-410", "Invalid sign public key provided"),
	MACHINE_NAME_EXISTS("KER-MSD-413", "Entry already found for the provided machine name"),
	MACHINE_KEYS_ALREADY_MAPPED("KER-MSD-414", "Entry already found for the provided public keys");
	
	private final String errorCode;
	private final String errorMessage;

	private MachineErrorCode(final String errorCode, final String errorMessage) {
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
