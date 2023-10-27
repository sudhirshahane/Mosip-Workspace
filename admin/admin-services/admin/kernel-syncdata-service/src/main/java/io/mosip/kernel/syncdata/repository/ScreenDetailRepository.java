package io.mosip.kernel.syncdata.repository;

import java.time.LocalDateTime;
import java.util.List;

import io.mosip.kernel.syncdata.dto.EntityDtimes;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import io.mosip.kernel.syncdata.entity.ScreenDetail;
import io.mosip.kernel.syncdata.entity.id.IdAndLanguageCodeID;

/**
 * @author Srinivasan
 * @since 1.0.0 The Interface ScreenDetailRepository.
 */
@Repository
public interface ScreenDetailRepository extends JpaRepository<ScreenDetail, IdAndLanguageCodeID> {

	/**
	 * Find by last updated and current time stamp.
	 *
	 * @param lastUpdateTimeStamp the last update time stamp
	 * @param currentTimeStamp    the current time stamp
	 * @return the list
	 */
	@Cacheable(cacheNames = "initial-sync", key = "'screen_detail'", condition = "#a0.getYear() <= 1970")
	@Query("FROM ScreenDetail WHERE (createdDateTime BETWEEN ?1 AND ?2 ) OR (updatedDateTime BETWEEN ?1 AND ?2 )  OR (deletedDateTime BETWEEN ?1 AND ?2 )")
	List<ScreenDetail> findByLastUpdatedAndCurrentTimeStamp(LocalDateTime lastUpdateTimeStamp,
			LocalDateTime currentTimeStamp);

	@Cacheable(cacheNames = "delta-sync", key = "'screen_detail'")
	@Query(value = "select new io.mosip.kernel.syncdata.dto.EntityDtimes(max(aam.createdDateTime), max(aam.updatedDateTime), max(aam.deletedDateTime)) from ScreenDetail aam ")
	EntityDtimes getMaxCreatedDateTimeMaxUpdatedDateTime();
}
