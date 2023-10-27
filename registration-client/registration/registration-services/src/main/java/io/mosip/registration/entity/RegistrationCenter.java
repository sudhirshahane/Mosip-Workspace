package io.mosip.registration.entity;

import java.sql.Time;
import java.sql.Timestamp;
import java.util.List;

import javax.persistence.Column;
import javax.persistence.EmbeddedId;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.OneToMany;
import javax.persistence.Table;

import io.mosip.registration.entity.id.RegistartionCenterId;
import lombok.Getter;
import lombok.Setter;

/**
 * The Entity Class for Registration Center details
 * 
 * @author Sravya Surampalli
 * @since 1.0.0
 */
@Entity
@Table(schema = "reg", name = "registration_center")
@Getter
@Setter
public class RegistrationCenter extends RegistrationCommonFields {

	@EmbeddedId
	private RegistartionCenterId registartionCenterId;
	
	@Column(name = "name")
	private String name;
	@Column(name = "cntrtyp_code")
	private String centerTypeCode;
	@Column(name = "addr_line1")
	private String addressLine1;
	@Column(name = "addr_line2")
	private String addressLine2;
	@Column(name = "addr_line3")
	private String addressLine3;
	@Column(name = "latitude")
	private String latitude;
	@Column(name = "longitude")
	private String longitude;
	@Column(name = "location_Code")
	private String locationCode;
	@Column(name = "contact_phone")
	private String contactPhone;
	@Column(name = "contact_person")
	private String contactPerson;
	@Column(name = "number_of_kiosks")
	private Integer numberOfKiosks;
	@Column(name = "working_hours")
	private String workingHours;
	@Column(name = "per_kiosk_process_time")
	private Time perKioskProcessTime;
	@Column(name = "center_start_time")
	private Time centerStartTime;
	@Column(name = "center_end_time")
	private Time centerEndTime;
	@Column(name = "lunch_start_time")
	private Time lunchStartTime;
	@Column(name = "lunch_end_time")
	private Time lunchEndTime;
	@Column(name = "time_zone")
	private String timeZone;
	@Column(name = "holiday_loc_code")
	private String holidayLocationCode;
	@Column(name = "is_deleted")
	private Boolean isDeleted;
	@Column(name = "del_dtimes")
	private Timestamp delDtimes;

}
