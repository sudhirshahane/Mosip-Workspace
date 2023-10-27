package io.mosip.registration.jobs.impl;

import static io.mosip.registration.constants.RegistrationConstants.APPLICATION_ID;
import static io.mosip.registration.constants.RegistrationConstants.APPLICATION_NAME;

import io.mosip.kernel.core.util.DateUtils;
import org.quartz.JobExecutionContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

import io.mosip.kernel.core.exception.ExceptionUtils;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.registration.config.AppConfig;
import io.mosip.registration.constants.LoggerConstants;
import io.mosip.registration.constants.RegistrationConstants;
import io.mosip.registration.dto.ResponseDTO;
import io.mosip.registration.exception.RegBaseCheckedException;
import io.mosip.registration.exception.RegBaseUncheckedException;
import io.mosip.registration.jobs.BaseJob;
import io.mosip.registration.service.sync.PolicySyncService;

import java.sql.Timestamp;

/**
 * This is a job for Key Policy Sync.
 * 
 * <p>
 * This Job will be automatically triggered based on sync_frequency which has in
 * local DB.
 * </p>
 * 
 * <p>
 * If Sync_frequency = "0 0 11 * * ?" this job will be triggered everyday 11:00
 * AM, if it was missed on 11:00 AM, trigger on immediate application launch.
 * </p>
 * 
 * @author Brahmananda Reddy
 * @since 1.0.0
 *
 */
@Component(value = "keyPolicySyncJob")
public class KeyPolicySyncJob extends BaseJob {

	/**
	 * The PolicySyncService
	 */
	@Autowired
	private PolicySyncService policySyncService;

	/**
	 * LOGGER for logging
	 */
	private static final Logger LOGGER = AppConfig.getLogger(KeyPolicySyncJob.class);

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.springframework.scheduling.quartz.QuartzJobBean#executeInternal(org.
	 * quartz.JobExecutionContext)
	 */
	@Async
	@Override
	public void executeInternal(JobExecutionContext context) {
		LOGGER.info(LoggerConstants.KEY_POLICY_SYNC_JOB_TITLE, RegistrationConstants.APPLICATION_NAME,
				RegistrationConstants.APPLICATION_ID, "job execute internal started");
		this.responseDTO = new ResponseDTO();

		try {

			this.jobId = loadContext(context);
			policySyncService = applicationContext.getBean(PolicySyncService.class);

			// Execute Parent Job
			this.responseDTO = executeParentJob(jobId);

			// Execute Current Job
			if (responseDTO.getSuccessResponseDTO() != null) {
				this.responseDTO = policySyncService.fetchPolicy();
			}

			syncTransactionUpdate(responseDTO, triggerPoint, jobId, Timestamp.valueOf(DateUtils.getUTCCurrentDateTime()));

		} catch (RegBaseUncheckedException baseUncheckedException) {
			LOGGER.error(LoggerConstants.KEY_POLICY_SYNC_JOB_TITLE, RegistrationConstants.APPLICATION_NAME,
					RegistrationConstants.APPLICATION_ID, baseUncheckedException.getMessage());
			throw baseUncheckedException;
		} catch (RegBaseCheckedException checkedException) {

			LOGGER.error(LoggerConstants.KEY_POLICY_SYNC_JOB_TITLE, APPLICATION_NAME, APPLICATION_ID,
					ExceptionUtils.getStackTrace(checkedException));
		}

		LOGGER.info(LoggerConstants.KEY_POLICY_SYNC_JOB_TITLE, RegistrationConstants.APPLICATION_NAME,
				RegistrationConstants.APPLICATION_ID, "job execute internal Ended");

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see io.mosip.registration.jobs.BaseJob#executeJob(java.lang.String,
	 * java.lang.String)
	 */
	@Override
	public ResponseDTO executeJob(String triggerPoint, String jobId) {

		LOGGER.info(LoggerConstants.KEY_POLICY_SYNC_JOB_TITLE, RegistrationConstants.APPLICATION_NAME,
				RegistrationConstants.APPLICATION_ID, "execute Job started");

		try {// Execute Parent Job
			this.responseDTO = executeParentJob(jobId);

			// Execute Current Job
			if (responseDTO.getSuccessResponseDTO() != null) {
				this.responseDTO = policySyncService.fetchPolicy();
			}
		} catch (RegBaseCheckedException checkedException) {

			LOGGER.error(LoggerConstants.KEY_POLICY_SYNC_JOB_TITLE, APPLICATION_NAME, APPLICATION_ID,
					ExceptionUtils.getStackTrace(checkedException));
		}
		syncTransactionUpdate(responseDTO, triggerPoint, jobId, Timestamp.valueOf(DateUtils.getUTCCurrentDateTime()));

		LOGGER.info(LoggerConstants.KEY_POLICY_SYNC_JOB_TITLE, RegistrationConstants.APPLICATION_NAME,
				RegistrationConstants.APPLICATION_ID, "execute job ended");

		return responseDTO;

	}

}
