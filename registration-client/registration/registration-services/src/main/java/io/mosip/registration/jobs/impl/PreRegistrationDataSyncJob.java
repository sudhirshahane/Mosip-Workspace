package io.mosip.registration.jobs.impl;

import java.sql.Timestamp;

import org.quartz.DisallowConcurrentExecution;
import org.quartz.JobExecutionContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

import io.mosip.kernel.core.exception.ExceptionUtils;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.registration.config.AppConfig;
import io.mosip.registration.constants.LoggerConstants;
import io.mosip.registration.constants.RegistrationConstants;
import io.mosip.registration.dto.ResponseDTO;
import io.mosip.registration.exception.RegBaseUncheckedException;
import io.mosip.registration.jobs.BaseJob;
import io.mosip.registration.service.sync.PreRegistrationDataSyncService;

/**
 * The {@code PreRegistrationDataSyncJob} is a job to sync the pre registrations
 * 
 * <p>
 * The {@code PreRegistrationDataSyncJob} is job to sync the pre-registration
 * data from server to local.
 * </p>
 * 
 * <p>
 * The PreRegistration packets will be saved on configured folder (EX:
 * PreRegistartion Packet Store).
 * </p>
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
 * @author YASWANTH S
 * @since 1.0.0
 *
 */
@DisallowConcurrentExecution
@Component(value = "preRegistrationDataSyncJob")
public class PreRegistrationDataSyncJob extends BaseJob {

	private static final Logger LOGGER = AppConfig.getLogger(PreRegistrationDataSyncJob.class);

	@Autowired
	PreRegistrationDataSyncService preRegistrationDataSyncService;

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.springframework.scheduling.quartz.QuartzJobBean#executeInternal(org.
	 * quartz.JobExecutionContext)
	 */
	@Async
	@Override
	public void executeInternal(JobExecutionContext context) {
		LOGGER.info(LoggerConstants.PRE_REG_DATA_SYNC_JOB_LOGGER_TITLE, RegistrationConstants.APPLICATION_NAME,
				RegistrationConstants.APPLICATION_ID, "job execute internal started");
		this.responseDTO = new ResponseDTO();

		try {
			this.jobId = loadContext(context);
			preRegistrationDataSyncService = applicationContext.getBean(PreRegistrationDataSyncService.class);

			// Execute Parent Job
			this.responseDTO = executeParentJob(jobId);

			// Execute Current Job
			if (responseDTO.getSuccessResponseDTO() != null) {
				this.responseDTO = preRegistrationDataSyncService
						.getPreRegistrationIds(RegistrationConstants.OPT_TO_REG_PDS_J00003);
			}

			syncTransactionUpdate(responseDTO, triggerPoint, jobId, Timestamp.valueOf(DateUtils.getUTCCurrentDateTime()));

		} catch (RegBaseUncheckedException baseUncheckedException) {
			LOGGER.error(LoggerConstants.PRE_REG_DATA_SYNC_JOB_LOGGER_TITLE, RegistrationConstants.APPLICATION_NAME,
					RegistrationConstants.APPLICATION_ID,
					baseUncheckedException.getMessage() + ExceptionUtils.getStackTrace(baseUncheckedException));
			throw baseUncheckedException;
		}

		LOGGER.info(LoggerConstants.PRE_REG_DATA_SYNC_JOB_LOGGER_TITLE, RegistrationConstants.APPLICATION_NAME,
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

		LOGGER.info(LoggerConstants.PRE_REG_DATA_SYNC_JOB_LOGGER_TITLE, RegistrationConstants.APPLICATION_NAME,
				RegistrationConstants.APPLICATION_ID, "execute Job started");

		// Execute Parent Job
		this.responseDTO = executeParentJob(jobId);

		// Execute Current Job
		if (responseDTO.getSuccessResponseDTO() != null) {
			this.responseDTO = preRegistrationDataSyncService.getPreRegistrationIds(RegistrationConstants.OPT_TO_REG_PDS_J00003);
		}
		syncTransactionUpdate(responseDTO, triggerPoint, jobId, Timestamp.valueOf(DateUtils.getUTCCurrentDateTime()));

		LOGGER.info(LoggerConstants.PRE_REG_DATA_SYNC_JOB_LOGGER_TITLE, RegistrationConstants.APPLICATION_NAME,
				RegistrationConstants.APPLICATION_ID, "execute job ended");

		return responseDTO;

	}

}
