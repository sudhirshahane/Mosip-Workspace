package io.mosip.registration.repositories;

import java.util.List;

import io.mosip.kernel.core.dataaccess.spi.repository.BaseRepository;
import io.mosip.registration.entity.DocumentCategory;

/**
 * Interface for {@link DocumentCategory}
 * 
 * @author Brahmananda Reddy
 *
 */
public interface DocumentCategoryRepository extends BaseRepository<DocumentCategory, String> {

	List<DocumentCategory> findByIsActiveTrueAndLangCode(String langCode);

	List<DocumentCategory> findAllByIsActiveTrue();

	DocumentCategory findByIsActiveTrueAndCodeAndLangCode(String docCategeoryCode, String langCode);
	
	DocumentCategory findByIsActiveTrueAndCodeAndNameAndLangCode(String docCategeoryCode,String docName, String langCode);

}
