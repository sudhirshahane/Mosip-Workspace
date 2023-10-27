package io.mosip.registration.entity;

import java.io.Serializable;

import javax.persistence.AttributeOverride;
import javax.persistence.AttributeOverrides;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.IdClass;
import javax.persistence.Table;

import io.mosip.registration.entity.id.WordAndLanguageCodeID;

/**
 * This Entity Class contains the list of words which were not allowed during Registration process 
 * with respect to language code.
 * The data for this table will come through sync from server master table
 * 
 * @author Sreekar Chukka
 * @since 1.0.0
 */

@Entity
@Table(name = "blocklisted_words", schema = "reg")
@IdClass(WordAndLanguageCodeID.class)
public class BlocklistedWords extends RegistrationCommonFields implements Serializable {

	/**
	 * Serialized version ID.
	 */
	private static final long serialVersionUID = -402658536057675404L;

	@Id
	@AttributeOverrides({ @AttributeOverride(name = "word", column = @Column(name = "word")),
			@AttributeOverride(name = "langCode", column = @Column(name = "lang_code")) })
	/**
	 * The blocklisted word.
	 */
	private String word;

	/**
	 * The language code of the word.
	 */
	private String langCode;

	/**
	 * The description of the word.
	 */
	@Column(name = "descr")
	private String description;

	/**
	 * @return the word
	 */
	public String getWord() {
		return word;
	}

	/**
	 * @param word the word to set
	 */
	public void setWord(String word) {
		this.word = word;
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

	/**
	 * @return the description
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * @param description the description to set
	 */
	public void setDescription(String description) {
		this.description = description;
	}

}
