package io.mosip.kernel.syncdata.entity;

import java.io.Serializable;

import javax.persistence.AttributeOverride;
import javax.persistence.AttributeOverrides;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.IdClass;
import javax.persistence.JoinColumn;
import javax.persistence.JoinColumns;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

import io.mosip.kernel.syncdata.entity.id.IdAndLanguageCodeID;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

/**
 * 
 * Entity for Device Specification Details
 * 
 * @author Uday
 * @author Megha Tanga
 * 
 *
 */
@EqualsAndHashCode(callSuper = true)
@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "device_spec", schema = "master")
public class DeviceSpecification extends BaseEntity implements Serializable {
	/**
	* 
	*/
	private static final long serialVersionUID = 1L;

	@Id
	@Column(name = "id", nullable = false, length = 36)
	private String id;

	@Column(name = "lang_code", length = 3)
	private String langCode;

	@Column(name = "name", nullable = false, length = 64)
	private String name;

	@Column(name = "brand", nullable = false, length = 32)
	private String brand;

	@Column(name = "model", nullable = false, length = 16)
	private String model;

	@Column(name = "dtyp_code", nullable = false, length = 36)
	private String deviceTypeCode;

	@Column(name = "min_driver_ver", nullable = false, length = 16)
	private String minDriverversion;

	@Column(name = "descr", length = 256)
	private String description;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "dtyp_code", referencedColumnName = "code", insertable = false, updatable = false)
	private DeviceType deviceType;

}
