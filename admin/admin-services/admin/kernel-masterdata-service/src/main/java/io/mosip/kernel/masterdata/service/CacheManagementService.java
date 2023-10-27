package io.mosip.kernel.masterdata.service;

import io.mosip.kernel.masterdata.utils.CacheName;

/**
 * @author GOVINDARAJ VELU
 *
 */
public interface CacheManagementService {

	void clearCacheByCacheName(CacheName cacheName);
	
	void clearCache();
}
