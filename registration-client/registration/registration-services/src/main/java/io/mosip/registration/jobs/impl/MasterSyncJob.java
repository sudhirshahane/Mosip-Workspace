package io.mosip.registration.jobs.impl;

import static io.mosip.registration.constants.RegistrationConstants.APPLICATION_ID;
import static io.mosip.registration.constants.RegistrationConstants.APPLICATION_NAME;

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
import io.mosip.registration.service.sync.MasterSyncService;

/**
 * This is a job to sync the master data
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
 * @author Sreekar Chukka
 *
 * @since 1.0.0
 */
@Component(value = "masterSyncJob")
public class MasterSyncJob extends BaseJob {

	/**
	 * The masterSyncService
	 */
	@Autowired
	private MasterSyncService masterSyncService;

	/**
	 * LOGGER for logging
	 */
	private static final Logger LOGGER = AppConfig.getLogger(MasterSyncJob.class);

	/**
	 * Execute internal.
	 *
	 * @param context
	 *            the context
	 */
	/*
	 * (non-Javadoc)
	 * 
	 * @see org.springframework.scheduling.quartz.QuartzJobBean#executeInternal(org.
	 * quartz.JobExecutionContext)
	 */
	@Async
	@Override
	public void executeInternal(JobExecutionContext context) {
		LOGGER.info(LoggerConstants.MASTER_SYNC_STATUS_JOB_TITLE, RegistrationConstants.APPLICATION_NAME,
				RegistrationConstants.APPLICATION_ID, "job execute internal started");
		this.responseDTO = new ResponseDTO();

		try {
			this.jobId = loadContext(context);
			masterSyncService = applicationContext.getBean(MasterSyncService.class);

			// Execute Parent Job
			this.responseDTO = executeParentJob(jobId);

			// Execute Current Job
			if (responseDTO.getSuccessResponseDTO() != null) {
				this.responseDTO = masterSyncService.getMasterSync(jobId, triggerPoint);
			}

			syncTransactionUpdate(responseDTO, triggerPoint, jobId, null);

		} catch (RegBaseUncheckedException baseUncheckedException) {
			LOGGER.error(LoggerConstants.MASTER_SYNC_STATUS_JOB_TITLE, RegistrationConstants.APPLICATION_NAME,
					RegistrationConstants.APPLICATION_ID,
					baseUncheckedException.getMessage() + ExceptionUtils.getStackTrace(baseUncheckedException));
			throw baseUncheckedException;
		} catch (RegBaseCheckedException checkedException) {
			LOGGER.error(LoggerConstants.USER_DETAIL_SERVICE_JOB_TITLE, APPLICATION_NAME, APPLICATION_ID,
					ExceptionUtils.getStackTrace(checkedException));
		}

		LOGGER.info(LoggerConstants.MASTER_SYNC_STATUS_JOB_TITLE, RegistrationConstants.APPLICATION_NAME,
				RegistrationConstants.APPLICATION_ID, "job execute internal Ended");
	}

	@Override
	public ResponseDTO executeJob(String triggerPoint, String jobId) {

		LOGGER.info(LoggerConstants.MASTER_SYNC_STATUS_JOB_TITLE, RegistrationConstants.APPLICATION_NAME,
				RegistrationConstants.APPLICATION_ID, "execute Job started");

		try {
			this.responseDTO = masterSyncService.getMasterSync(jobId, triggerPoint);
		} catch (RegBaseCheckedException checkedException) {
			LOGGER.error(LoggerConstants.USER_DETAIL_SERVICE_JOB_TITLE, APPLICATION_NAME, APPLICATION_ID,
					ExceptionUtils.getStackTrace(checkedException));
		}
		syncTransactionUpdate(responseDTO, triggerPoint, jobId, null);

		LOGGER.info(LoggerConstants.MASTER_SYNC_STATUS_JOB_TITLE, RegistrationConstants.APPLICATION_NAME,
				RegistrationConstants.APPLICATION_ID, "execute job ended");

		return responseDTO;
	}

}
