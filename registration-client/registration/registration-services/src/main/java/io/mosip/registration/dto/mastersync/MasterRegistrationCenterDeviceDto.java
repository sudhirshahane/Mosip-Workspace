package io.mosip.registration.dto.mastersync;

/**
 * 
 * @author Sreekar Chukka
 * @since 1.0.0
 */

public class MasterRegistrationCenterDeviceDto extends MasterSyncBaseDto{

	
	private String regCenterId;

	
	private String deviceId;

	
	private Boolean isActive;


	/**
	 * @return the regCenterId
	 */
	public String getRegCenterId() {
		return regCenterId;
	}


	/**
	 * @param regCenterId the regCenterId to set
	 */
	public void setRegCenterId(String regCenterId) {
		this.regCenterId = regCenterId;
	}


	/**
	 * @return the deviceId
	 */
	public String getDeviceId() {
		return deviceId;
	}


	/**
	 * @param deviceId the deviceId to set
	 */
	public void setDeviceId(String deviceId) {
		this.deviceId = deviceId;
	}


	/**
	 * @return the isActive
	 */
	public Boolean getIsActive() {
		return isActive;
	}


	/**
	 * @param isActive the isActive to set
	 */
	public void setIsActive(Boolean isActive) {
		this.isActive = isActive;
	}
	
	

}
