package io.mosip.registration.dao.impl;

import static io.mosip.registration.constants.RegistrationConstants.APPLICATION_ID;
import static io.mosip.registration.constants.RegistrationConstants.APPLICATION_NAME;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.registration.config.AppConfig;
import io.mosip.registration.dao.SyncJobConfigDAO;
import io.mosip.registration.entity.SyncJobDef;
import io.mosip.registration.repositories.JobConfigRepository;

/**
 * implementation class of {@link SyncJobConfigDAO}
 * 
 * @author Dinesh Ashokan
 *
 */
@Repository
public class SyncJobConfigDAOImpl implements SyncJobConfigDAO {

	@Autowired
	private JobConfigRepository jobConfigRepository;

	/** Object for Logger. */
	private static final Logger LOGGER = AppConfig.getLogger(SyncJobConfigDAOImpl.class);

	/*
	 * (non-Javadoc)
	 * 
	 * @see io.mosip.registration.dao.JobConfigDAO#getJob()
	 */
	@Override
	public List<SyncJobDef> getAll() {
		LOGGER.info("REGISTRATION-JOB_CONFIF_DAO", APPLICATION_NAME, APPLICATION_ID, "Get all Sync Jobs");

		return jobConfigRepository.findAll();
	}
	
	@Override
	public SyncJobDef getSyncJob(String jobId) {
		LOGGER.info("Getting SyncJob for " + jobId);
		Optional<SyncJobDef> syncJobDef = jobConfigRepository.findById(jobId);
		return syncJobDef.isPresent() ? syncJobDef.get() : null;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see io.mosip.registration.dao.SyncJobConfigDAO#getActiveJobs()
	 */
	@Override
	public List<SyncJobDef> getActiveJobs() {
		LOGGER.info("REGISTRATION-JOB_CONFIF_DAO", APPLICATION_NAME, APPLICATION_ID, "Get all active Sync Jobs");
		return jobConfigRepository.findByIsActiveTrue();
	}

	/* (non-Javadoc)
	 * @see io.mosip.registration.dao.SyncJobConfigDAO#updateAll(java.util.List)
	 */
	@Override
	public List<SyncJobDef> updateAll(List<SyncJobDef> syncJobDefs) {
		LOGGER.info("REGISTRATION-JOB_CONFIF_DAO", APPLICATION_NAME, APPLICATION_ID, "Update all active Sync Jobs");
		return jobConfigRepository.saveAll(syncJobDefs);
	}

}
