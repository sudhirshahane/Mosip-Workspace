package io.mosip.registration.entity;

import java.io.Serializable;
import java.sql.Timestamp;

import javax.persistence.Column;
import javax.persistence.EmbeddedId;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.JoinColumns;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

import org.hibernate.annotations.NotFound;
import org.hibernate.annotations.NotFoundAction;

import io.mosip.registration.entity.id.UserMachineMappingID;

/**
 * The Entity Class for User Machine Mapping.
 * 
 * @author Sreekar Chukka
 * @since 1.0.0
 */
@Entity
@Table(schema = "reg", name = "reg_center_user_machine")
public class UserMachineMapping extends RegistrationCommonFields implements Serializable {

	/**
	 * serial Version UID
	 */
	private static final long serialVersionUID = 8686723876595925323L;

	/** The user machine mapping id. */
	@EmbeddedId
	private UserMachineMappingID userMachineMappingId;

	/** The user detail. */
	@ManyToOne(fetch=FetchType.EAGER)
	@NotFound(action=NotFoundAction.IGNORE)
	@JoinColumn(name = "usr_id", nullable = false, insertable = false, updatable = false)
	private UserDetail userDetail;

	/** The machine master. */
	@ManyToOne(fetch=FetchType.EAGER)
	@JoinColumns({
			@JoinColumn(name = "machine_id", referencedColumnName = "id", insertable = false, updatable = false) })
	private MachineMaster machineMaster;

	/** The is deleted. */
	@Column(name = "is_deleted")
	private Boolean isDeleted;

	/** The deleted date time. */
	@Column(name = "del_dtimes")
	private Timestamp deletedDateTime;

	/** The lang code. */
	@Column(name = "lang_code")
	private String langCode;

	/**
	 * @return the langCode
	 */
	public String getLangCode() {
		return langCode;
	}

	/**
	 * @param langCode the langCode to set
	 */
	public void setLangCode(String langCode) {
		this.langCode = langCode;
	}

	/**
	 * @return the isDeleted
	 */
	public Boolean getIsDeleted() {
		return isDeleted;
	}

	/**
	 * @param isDeleted the isDeleted to set
	 */
	public void setIsDeleted(Boolean isDeleted) {
		this.isDeleted = isDeleted;
	}

	/**
	 * @return the userMachineMappingId
	 */
	public UserMachineMappingID getUserMachineMappingId() {
		return userMachineMappingId;
	}

	/**
	 * @param userMachineMappingId the userMachineMappingId to set
	 */
	public void setUserMachineMappingId(UserMachineMappingID userMachineMappingId) {
		this.userMachineMappingId = userMachineMappingId;
	}

	/**
	 * @return the userDetail
	 */
	public UserDetail getUserDetail() {
		return userDetail;
	}

	/**
	 * @param userDetail the userDetail to set
	 */
	public void setUserDetail(UserDetail userDetail) {
		this.userDetail = userDetail;
	}

	/**
	 * @return the machineMaster
	 */
	public MachineMaster getMachineMaster() {
		return machineMaster;
	}

	/**
	 * @param machineMaster the machineMaster to set
	 */
	public void setMachineMaster(MachineMaster machineMaster) {
		this.machineMaster = machineMaster;
	}

	/**
	 * @return the isDeleted
	 */
	public Boolean isDeleted() {
		return isDeleted;
	}

	/**
	 * @param isDeleted the isDeleted to set
	 */
	public void setDeleted(Boolean isDeleted) {
		this.isDeleted = isDeleted;
	}

	/**
	 * @return the deletedDateTime
	 */
	public Timestamp getDeletedDateTime() {
		return deletedDateTime;
	}

	/**
	 * @param deletedDateTime the deletedDateTime to set
	 */
	public void setDeletedDateTime(Timestamp deletedDateTime) {
		this.deletedDateTime = deletedDateTime;
	}

}