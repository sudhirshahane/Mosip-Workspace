package io.mosip.kernel.syncdata.repository;

import java.time.LocalDateTime;
import java.util.List;

import io.mosip.kernel.syncdata.dto.EntityDtimes;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import io.mosip.kernel.syncdata.entity.ReasonList;

/**
 * 
 * @author Srinivasan
 *
 */
public interface ReasonListRepository extends JpaRepository<ReasonList, String> {
	/**
	 * Method to find list of ReasonList created , updated or deleted time is
	 * greater than lastUpdated timeStamp.
	 * 
	 * @param lastUpdated      timeStamp - last updated timestamp
	 * @param currentTimeStamp - currentTimestamp
	 * @return list of {@link ReasonList} -list of reason list
	 */
	@Cacheable(cacheNames = "initial-sync", key = "'reason_list'", condition = "#a0.getYear() <= 1970")
	@Query("FROM ReasonList WHERE (createdDateTime BETWEEN ?1 AND ?2) OR (updatedDateTime BETWEEN ?1 AND ?2)  OR (deletedDateTime BETWEEN ?1 AND ?2)")
	List<ReasonList> findAllLatestCreatedUpdateDeleted(LocalDateTime lastUpdated, LocalDateTime currentTimeStamp);

	@Cacheable(cacheNames = "delta-sync", key = "'reason_list'")
	@Query(value = "select new io.mosip.kernel.syncdata.dto.EntityDtimes(max(aam.createdDateTime), max(aam.updatedDateTime), max(aam.deletedDateTime)) from ReasonList aam ")
	EntityDtimes getMaxCreatedDateTimeMaxUpdatedDateTime();
}
