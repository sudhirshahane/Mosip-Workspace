package io.mosip.registration.entity;

import java.sql.Timestamp;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

import io.mosip.kernel.core.util.DateUtils;
/**
 * The Entity class for sync job def
 * 
 * @author Dinesh Ashokan
 * @since 1.0.0
 *
 */
@Entity
@Table(schema = "reg", name = "sync_job_def")
public class SyncJobDef extends RegistrationCommonFields {
	@Id
	@Column(name = "id")
	private String id;
	@Column(name = "name")
	private String name;
	@Column(name = "api_name")
	private String apiName;
	@Column(name = "parent_syncjob_id")
	private String parentSyncJobId;
	@Column(name = "sync_freq")
	private String syncFreq;
	@Column(name = "lock_duration")
	private String lockDuration;
	@Column(name = "lang_code")
	private String langCode;

	@Column(name = "is_deleted")
	private Boolean isDeleted;
	@Column(name = "del_dtimes")
	private Timestamp deletedDateTime;
	@Column(name = "job_type")
	private String jobType;

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getApiName() {
		return apiName;
	}

	public void setApiName(String apiName) {
		this.apiName = apiName;
	}

	public String getParentSyncJobId() {
		return parentSyncJobId;
	}

	public void setParentSyncJobId(String parentSyncJobId) {
		this.parentSyncJobId = parentSyncJobId;
	}

	public String getSyncFreq() {
		return syncFreq;
	}

	public void setSyncFreq(String syncFreq) {
		this.syncFreq = syncFreq;
	}

	public String getLockDuration() {
		return lockDuration;
	}

	public void setLockDuration(String lockDuration) {
		this.lockDuration = lockDuration;
	}

	public String getLangCode() {
		return langCode;
	}

	public void setLangCode(String langCode) {
		this.langCode = langCode;
	}

	public Boolean getIsDeleted() {
		return isDeleted;
	}

	public void setIsDeleted(Boolean isDeleted) {
		this.isDeleted = isDeleted;
	}

	public Timestamp getDeletedDateTime() {
		return deletedDateTime;
	}

	public void setDeletedDateTime(Timestamp deletedDateTime) {
		this.deletedDateTime = Timestamp.valueOf(DateUtils.getUTCCurrentDateTime());
	}

	public String getJobType() {
		return jobType;
	}

	public void setJobType(String jobType) {
		this.jobType = jobType;
	}
}
