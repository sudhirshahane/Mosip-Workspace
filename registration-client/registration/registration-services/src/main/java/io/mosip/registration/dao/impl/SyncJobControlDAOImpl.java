package io.mosip.registration.dao.impl;

import static io.mosip.registration.constants.RegistrationConstants.APPLICATION_ID;
import static io.mosip.registration.constants.RegistrationConstants.APPLICATION_NAME;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.registration.audit.AuditManagerService;
import io.mosip.registration.config.AppConfig;
import io.mosip.registration.constants.AuditEvent;
import io.mosip.registration.constants.AuditReferenceIdTypes;
import io.mosip.registration.constants.Components;
import io.mosip.registration.constants.RegistrationClientStatusCode;
import io.mosip.registration.constants.RegistrationConstants;
import io.mosip.registration.context.SessionContext;
import io.mosip.registration.dao.SyncJobControlDAO;
import io.mosip.registration.entity.Registration;
import io.mosip.registration.entity.SyncControl;
import io.mosip.registration.exception.RegBaseUncheckedException;
import io.mosip.registration.repositories.RegistrationRepository;
import io.mosip.registration.repositories.SyncJobControlRepository;

/**
 * The implementation class for {@link SyncJobControlDAO}.
 *
 * @author Sreekar Chukka
 * @author Mahesh Kumar
 * @since 1.0.0
 */
@Repository
public class SyncJobControlDAOImpl implements SyncJobControlDAO {

	private static final List<String> REG_STATUS_CODES = Arrays.asList(RegistrationClientStatusCode.CREATED.getCode(),
			RegistrationClientStatusCode.REJECTED.getCode(), RegistrationClientStatusCode.APPROVED.getCode(),
			RegistrationClientStatusCode.CORRECTION.getCode(), RegistrationClientStatusCode.UIN_UPDATE.getCode(),
			RegistrationClientStatusCode.UIN_LOST.getCode(),
			RegistrationClientStatusCode.META_INFO_SYN_SERVER.getCode(),
			RegistrationClientStatusCode.ON_HOLD.getCode());

	private static final List<String> LAST_EXPORT_STATUS_CODES = Arrays.asList(
			RegistrationClientStatusCode.UPLOADED_SUCCESSFULLY.getCode(),
			RegistrationClientStatusCode.EXPORT.getCode());

	/** Object for Sync Status Repository. */
	@Autowired
	private SyncJobControlRepository syncJobRepository;

	/** Object for Registration Repository. */
	@Autowired
	private RegistrationRepository registrationRepository;

	/**
	 * Object for Logger
	 */
	private static final Logger LOGGER = AppConfig.getLogger(SyncJobControlDAOImpl.class);

	@Autowired
	private AuditManagerService auditFactory;

	/*
	 * (non-Javadoc)
	 * 
	 * @see io.mosip.registration.dao.SyncJobDAO#validateSyncStatus()
	 */
	public SyncJobInfo getSyncStatus() {

		LOGGER.info("REGISTRATION - SYNC - VALIDATION", APPLICATION_NAME, APPLICATION_ID,
				"Fetching the last sync details from database started");

		try {
			Long registrationsListCount = registrationRepository
					.countByClientStatusCodeInOrderByUpdDtimesDesc(REG_STATUS_CODES);
			Registration lastExportRegistration = registrationRepository
					.findTopByClientStatusCodeInOrderByUpdDtimesDesc(LAST_EXPORT_STATUS_CODES);

			LOGGER.info("REGISTRATION - SYNC - VALIDATION", APPLICATION_NAME, APPLICATION_ID,
					"Fetching the last sync details from database ended");

			auditFactory.audit(AuditEvent.SYNCJOB_INFO_FETCH, Components.SYNC_VALIDATE, SessionContext.userId(),
					AuditReferenceIdTypes.USER_ID.getReferenceTypeId());

			return new SyncJobInfo(syncJobRepository.findAll(), registrationsListCount, lastExportRegistration);

		} catch (RuntimeException runtimeException) {
			throw new RegBaseUncheckedException(RegistrationConstants.SYNC_STATUS_VALIDATE,
					runtimeException.toString());
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * io.mosip.registration.dao.SyncJobDAO#update(io.mosip.registration.entity.
	 * SyncControl)
	 */
	@Override
	public SyncControl update(SyncControl syncControl) {
		LOGGER.info(RegistrationConstants.SYNC_JOB_CONTROL_DAO_LOGGER_TITLE, APPLICATION_NAME, APPLICATION_ID,
				"updating sync details from database started");
		return syncJobRepository.update(syncControl);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see io.mosip.registration.dao.SyncJobDAO#save(io.mosip.registration.entity.
	 * SyncControl)
	 */
	@Override
	public SyncControl save(SyncControl syncControl) {
		LOGGER.info(RegistrationConstants.SYNC_JOB_CONTROL_DAO_LOGGER_TITLE, APPLICATION_NAME, APPLICATION_ID,
				"saving sync details to database started");
		return syncJobRepository.save(syncControl);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see io.mosip.registration.dao.SyncJobDAO#findBySyncJobId(java.lang.String)
	 */
	@Override
	public SyncControl findBySyncJobId(String syncJobId) {
		LOGGER.info(RegistrationConstants.SYNC_JOB_CONTROL_DAO_LOGGER_TITLE, APPLICATION_NAME, APPLICATION_ID,
				"Fetching the sync details from database started");
		return syncJobRepository.findBySyncJobId(syncJobId);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see io.mosip.registration.dao.SyncJobDAO#findAll()
	 */
	@Override
	public List<SyncControl> findAll() {
		LOGGER.info(RegistrationConstants.SYNC_JOB_CONTROL_DAO_LOGGER_TITLE, APPLICATION_NAME, APPLICATION_ID,
				"Fetching the list of sync details from database started");
		return syncJobRepository.findAll();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see io.mosip.registration.dao.SyncJobDAO#getRegistrationDetails()
	 */
	public List<Registration> getRegistrationDetails() {

		LOGGER.info(RegistrationConstants.SYNC_JOB_CONTROL_DAO_LOGGER_TITLE, APPLICATION_NAME, APPLICATION_ID,
				"Fetching the Registration Details of Registered Status");

		return registrationRepository
				.findByclientStatusCodeOrderByCrDtimeAsc(RegistrationClientStatusCode.CREATED.getCode());
	}
	
	@Override
	public Long getRegistrationCount() {
		LOGGER.info(RegistrationConstants.SYNC_JOB_CONTROL_DAO_LOGGER_TITLE, APPLICATION_NAME, APPLICATION_ID,
				"Fetching the total registration count of Registered Status");

		return registrationRepository
				.countByclientStatusCodeOrderByCrDtimeAsc(RegistrationClientStatusCode.CREATED.getCode());
	}

	@Override
	public Registration getFirstRegistration() {
		LOGGER.info(RegistrationConstants.SYNC_JOB_CONTROL_DAO_LOGGER_TITLE, APPLICATION_NAME, APPLICATION_ID,
				"Fetching the first registration from the list of registrations with Registered Status");

		return registrationRepository
				.findTopByclientStatusCodeOrderByCrDtimeAsc(RegistrationClientStatusCode.CREATED.getCode());
	}

}
