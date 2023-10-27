package io.mosip.registration.jobs.impl;

import static io.mosip.registration.constants.RegistrationConstants.APPLICATION_ID;
import static io.mosip.registration.constants.RegistrationConstants.APPLICATION_NAME;

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
import io.mosip.registration.exception.ConnectionException;
import io.mosip.registration.exception.RegBaseCheckedException;
import io.mosip.registration.exception.RegBaseUncheckedException;
import io.mosip.registration.jobs.BaseJob;
import io.mosip.registration.service.packet.RegPacketStatusService;

/**
 * The {@code PacketSyncStatusJob} is a job to sync the packet status
 * 
 * <p>
 * The {@code PacketSyncStatusJob} is a job which will get the status of a
 * packet (EX: PROCESSED) and update the same for associate registration in
 * local DataBase.
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
@Component(value = "packetSyncStatusJob")
public class PacketSyncStatusJob extends BaseJob {

	/**
	 * The RegPacketStatusServiceImpl
	 */
	@Autowired
	private RegPacketStatusService packetStatusService;

	/**
	 * LOGGER for logging
	 */
	private static final Logger LOGGER = AppConfig.getLogger(PacketSyncStatusJob.class);

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.springframework.scheduling.quartz.QuartzJobBean#executeInternal(org.
	 * quartz.JobExecutionContext)
	 */
	@Async
	@Override
	public void executeInternal(JobExecutionContext context) {
		LOGGER.info(LoggerConstants.PACKET_SYNC_STATUS_JOB_TITLE, RegistrationConstants.APPLICATION_NAME,
				RegistrationConstants.APPLICATION_ID, "job execute internal started");
		this.responseDTO = new ResponseDTO();

		try {

			this.jobId = loadContext(context);
			packetStatusService = applicationContext.getBean(RegPacketStatusService.class);

			// Execute Parent Job
			this.responseDTO = executeParentJob(jobId);

			// Execute Current Job
			if (responseDTO.getSuccessResponseDTO() != null) {
				this.responseDTO = packetStatusService.syncServerPacketStatusWithRetryWrapper(triggerPoint);
			}

			syncTransactionUpdate(responseDTO, triggerPoint, jobId, Timestamp.valueOf(DateUtils.getUTCCurrentDateTime()));

		} catch (RegBaseUncheckedException baseUncheckedException) {
			LOGGER.error(LoggerConstants.PRE_REG_DATA_SYNC_JOB_LOGGER_TITLE, RegistrationConstants.APPLICATION_NAME,
					RegistrationConstants.APPLICATION_ID,
					baseUncheckedException.getMessage() + ExceptionUtils.getStackTrace(baseUncheckedException));
			throw baseUncheckedException;
		} catch (RegBaseCheckedException | ConnectionException regBaseCheckedException) {
			LOGGER.error(LoggerConstants.PRE_REG_DATA_SYNC_JOB_LOGGER_TITLE, APPLICATION_NAME, APPLICATION_ID,
					regBaseCheckedException.getMessage() + ExceptionUtils.getStackTrace(regBaseCheckedException));
		}

		LOGGER.info(LoggerConstants.PACKET_SYNC_STATUS_JOB_TITLE, RegistrationConstants.APPLICATION_NAME,
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

		LOGGER.info(LoggerConstants.PACKET_SYNC_STATUS_JOB_TITLE, RegistrationConstants.APPLICATION_NAME,
				RegistrationConstants.APPLICATION_ID, "execute Job started");
		try {
			// Execute Parent Job
			this.responseDTO = executeParentJob(jobId);

			// Execute Current Job
			if (responseDTO.getSuccessResponseDTO() != null) {
				this.responseDTO = packetStatusService.syncServerPacketStatusWithRetryWrapper(triggerPoint);
			}
			syncTransactionUpdate(responseDTO, triggerPoint, jobId, Timestamp.valueOf(DateUtils.getUTCCurrentDateTime()));

			LOGGER.info(LoggerConstants.PACKET_SYNC_STATUS_JOB_TITLE, RegistrationConstants.APPLICATION_NAME,
					RegistrationConstants.APPLICATION_ID, "execute job ended");
		} catch (RegBaseCheckedException | ConnectionException regBaseCheckedException) {
			LOGGER.error(LoggerConstants.PACKET_SYNC_STATUS_JOB_TITLE, APPLICATION_NAME, APPLICATION_ID,
					regBaseCheckedException.getMessage() + ExceptionUtils.getStackTrace(regBaseCheckedException));
		}
		return responseDTO;
	}

}
