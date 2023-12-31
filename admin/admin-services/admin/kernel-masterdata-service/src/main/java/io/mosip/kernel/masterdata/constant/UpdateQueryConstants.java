package io.mosip.kernel.masterdata.constant;

/**
 * ENUM to handle the constants related to query updation.
 * 
 * @author Sagar Mahapatra
 *
 */
public enum UpdateQueryConstants {
	BLOCKLISTED_WORD_UPDATE_QUERY_WITHOUT_DESCRIPTION(
			"UPDATE BlocklistedWords bw SET bw.updatedBy = :updatedBy , bw.updatedDateTime = :updatedDateTime, bw.word = :word WHERE bw.word = :oldWord and  (bw.isDeleted is null or bw.isDeleted = false)"),
	BLOCKLISTED_WORD_UPDATE_QUERY_WITH_DESCRIPTION(
			"UPDATE BlocklistedWords bw SET bw.description = :description ,bw.updatedBy = :updatedBy , bw.updatedDateTime = :updatedDateTime, bw.word = :word  WHERE bw.word = :oldWord and (bw.isDeleted is null or bw.isDeleted = false)");

	/**
	 * The variable for query.
	 */
	private String query;

	/**
	 * Constructor to initialize the query value.
	 * 
	 * @param query the query value to be initialized.
	 */
	UpdateQueryConstants(String query) {
		this.query = query;
	}

	/**
	 * Getter for query.
	 * 
	 * @return the query.
	 */
	public String getQuery() {
		return this.query;
	}
}