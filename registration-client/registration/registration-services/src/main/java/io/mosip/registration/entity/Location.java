package io.mosip.registration.entity;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.IdClass;
import javax.persistence.Table;

import io.mosip.registration.entity.id.CodeAndLanguageCodeID;

/**
 * This Entity Class contains list of locations that are being used in Registration with respect to language code.
 * The data for this table will come through sync from server master table .
 *
 * @author Sreekar Chukka
 * @since 1.0.0
 */
@Entity
@Table(schema = "reg", name = "location")
@IdClass(CodeAndLanguageCodeID.class)
public class Location extends RegistrationCommonFields implements Serializable {

	private static final long serialVersionUID = -5585825705521742941L;

	@Id
	@Column(name = "code")
	private String code;

	@Id
	@Column(name = "lang_code")
	private String langCode;

	@Column(name = "name")
	private String name;

	@Column(name = "hierarchy_level")
	private int hierarchyLevel;

	@Column(name = "hierarchy_level_name")
	private String hierarchyName;

	@Column(name = "parent_loc_code")
	private String parentLocCode;

	/**
	 * @return the hierarchyLevel
	 */
	public int getHierarchyLevel() {
		return hierarchyLevel;
	}

	/**
	 * @param hierarchyLevel the hierarchyLevel to set
	 */
	public void setHierarchyLevel(int hierarchyLevel) {
		this.hierarchyLevel = hierarchyLevel;
	}

	/**
	 * @return the code
	 */
	public String getCode() {
		return code;
	}

	/**
	 * @param code the code to set
	 */
	public void setCode(String code) {
		this.code = code;
	}

	/**
	 * @return the name
	 */
	public String getName() {
		return name;
	}

	/**
	 * @param name the name to set
	 */
	public void setName(String name) {
		this.name = name;
	}

	/**
	 * @return the hierarchyName
	 */
	public String getHierarchyName() {
		return hierarchyName;
	}

	/**
	 * @param hierarchyName the hierarchyName to set
	 */
	public void setHierarchyName(String hierarchyName) {
		this.hierarchyName = hierarchyName;
	}

	/**
	 * @return the parentLocCode
	 */
	public String getParentLocCode() {
		return parentLocCode;
	}

	/**
	 * @param parentLocCode the parentLocCode to set
	 */
	public void setParentLocCode(String parentLocCode) {
		this.parentLocCode = parentLocCode;
	}

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

}
