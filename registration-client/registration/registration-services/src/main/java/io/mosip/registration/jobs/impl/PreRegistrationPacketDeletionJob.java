package io.mosip.registration.jobs.impl;

import static io.mosip.registration.constants.RegistrationConstants.APPLICATION_ID;
import static io.mosip.registration.constants.RegistrationConstants.APPLICATION_NAME;

import java.sql.Timestamp;
import java.util.LinkedList;

import io.mosip.kernel.core.util.DateUtils;
import org.quartz.JobExecutionContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.registration.config.AppConfig;
import io.mosip.registration.constants.RegistrationConstants;
import io.mosip.registration.dto.ErrorResponseDTO;
import io.mosip.registration.dto.ResponseDTO;
import io.mosip.registration.exception.RegBaseUncheckedException;
import io.mosip.registration.jobs.BaseJob;
import io.mosip.registration.service.sync.PreRegistrationDataSyncService;

/**
 * The {@code PreRegistrationPacketDeletionJob} Delete the Pre-Registration
 * Packets Based on the appointment date
 * 
 * <p>
 * The {@code PreRegistrationPacketDeletionJob} is to delete the
 * pre-registration data from in local.
 * </p>
 * 
 * <p>
 * The PreRegistration packets will be deleted in configured folder (EX:
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
 * @author M1046564
 *
 */
@Component(value = "preRegistrationPacketDeletionJob")
public class PreRegistrationPacketDeletionJob extends BaseJob {

	private static final Logger LOGGER = AppConfig.getLogger(PreRegistrationPacketDeletionJob.class);

	@Autowired
	private PreRegistrationDataSyncService preRegistrationDataSyncService;

	/*
	 * (non-Javadoc)
	 * 
	 * @see io.mosip.registration.jobs.BaseJob#executeJob(java.lang.String,
	 * java.lang.String)
	 */
	@Override
	public ResponseDTO executeJob(String triggerPoint, String jobId) {

		LOGGER.info("REGISTRATION - PRE_REG_PACKET_DELETION_STARTED_CHILD_JOB - PRE_REGISTRATION_PACKET_DELETION_JOB",
				APPLICATION_NAME, APPLICATION_ID, "Pre-Registration Packet Deletion job started");

		// Execute Parent Job
		this.responseDTO = executeParentJob(jobId);

		// Execute Current Job
		if (responseDTO.getSuccessResponseDTO() != null) {
			this.responseDTO = preRegistrationDataSyncService.fetchAndDeleteRecords();
		}

		syncTransactionUpdate(responseDTO, triggerPoint, jobId, Timestamp.valueOf(DateUtils.getUTCCurrentDateTime()));

		LOGGER.info("REGISTRATION - PRE_REG_PACKET_DELETION_CHILD_JOB_ENDED - PRE_REGISTRATION_PACKET_DELETION_JOB",
				APPLICATION_NAME, APPLICATION_ID, "Pre-Registration Packet Deletion job ended");

		return responseDTO;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.springframework.scheduling.quartz.QuartzJobBean#executeInternal(org.
	 * quartz.JobExecutionContext)
	 */
	@Override
	public void executeInternal(JobExecutionContext context) {
		LOGGER.info("REGISTRATION - PRE_REG_PACKET_DELETION_STARTED - PRE_REGISTRATION_PACKET_DELETION_JOB",
				APPLICATION_NAME, APPLICATION_ID, "Pre-Registration Packet Deletion job started");
		this.responseDTO = new ResponseDTO();

		try {
			this.jobId = loadContext(context);
			preRegistrationDataSyncService = applicationContext.getBean(PreRegistrationDataSyncService.class);

			// Execute Parent Job
			this.responseDTO = executeParentJob(jobId);

			// Execute Current Job
			if (responseDTO.getSuccessResponseDTO() != null) {
				try {
					// Run the Parent JOB always first
					this.responseDTO = preRegistrationDataSyncService.fetchAndDeleteRecords();

				} catch (RuntimeException exception) {
					LOGGER.error("PRE_REGISTRATION_PACKET_DELETION_JOB", RegistrationConstants.APPLICATION_NAME,
							RegistrationConstants.APPLICATION_ID, exception.getMessage());
					ErrorResponseDTO errorResponseDTO = new ErrorResponseDTO();
					LinkedList<ErrorResponseDTO> list = new LinkedList<>();
					list.add(errorResponseDTO);
					responseDTO.setErrorResponseDTOs(list);

				}
			}

			syncTransactionUpdate(responseDTO, triggerPoint, jobId, Timestamp.valueOf(DateUtils.getUTCCurrentDateTime()));

		} catch (RegBaseUncheckedException baseUncheckedException) {
			LOGGER.error("REGISTRATION - PRE_REG_PACKET_DELETION_ERROR - PRE_REGISTRATION_PACKET_DELETION_JOB",
					RegistrationConstants.APPLICATION_NAME, RegistrationConstants.APPLICATION_ID,
					baseUncheckedException.getMessage());
			throw baseUncheckedException;
		}

		LOGGER.info("REGISTRATION - PRE_REG_PACKET_DELETION_ENDED - PRE_REGISTRATION_PACKET_DELETION_JOB",
				APPLICATION_NAME, APPLICATION_ID, "Pre-Registration Packet Deletion job ended");

	}

}
