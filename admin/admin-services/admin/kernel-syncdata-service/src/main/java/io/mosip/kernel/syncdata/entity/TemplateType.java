package io.mosip.kernel.syncdata.entity;

import java.io.Serializable;

import javax.persistence.AttributeOverride;
import javax.persistence.AttributeOverrides;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.IdClass;
import javax.persistence.Table;

import io.mosip.kernel.syncdata.entity.id.CodeAndLanguageCodeID;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

/**
 * @author Uday Kumar
 * @since 1.0.0
 *
 */
@EqualsAndHashCode(callSuper = true)
@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "template_type", schema = "master")
public class TemplateType extends BaseEntity implements Serializable {

	private static final long serialVersionUID = -854194758755759037L;

	@Id
	@AttributeOverride(name = "code", column = @Column(name = "code", nullable = false, length = 36))
	private String code;

	@Column(name = "lang_code", length = 3)
	private String langCode;

	@Column(name = "descr", length = 256)
	private String description;
}
