package io.mosip.registration.service.packet.impl;

import static io.mosip.registration.constants.LoggerConstants.LOG_PKT_HANLDER;
import static io.mosip.registration.constants.RegistrationConstants.APPLICATION_ID;
import static io.mosip.registration.constants.RegistrationConstants.APPLICATION_NAME;
import static io.mosip.registration.exception.RegistrationExceptionConstants.REG_PACKET_CREATION_ERROR_CODE;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.Map.Entry;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import io.micrometer.core.annotation.Counted;
import io.micrometer.core.annotation.Timed;
import io.mosip.commons.packet.dto.PacketInfo;
import io.mosip.kernel.clientcrypto.service.impl.ClientCryptoFacade;
import io.mosip.kernel.clientcrypto.util.ClientCryptoUtils;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.kernel.core.util.FileUtils;
import io.mosip.kernel.core.util.HMACUtils2;
import io.mosip.kernel.core.util.JsonUtils;
import io.mosip.kernel.core.util.StringUtils;
import io.mosip.kernel.core.util.exception.JsonProcessingException;
import io.mosip.kernel.cryptomanager.dto.CryptomanagerRequestDto;
import io.mosip.registration.dto.schema.ProcessSpecDto;
import io.mosip.registration.entity.MachineMaster;
import io.mosip.registration.enums.FlowType;
import io.mosip.registration.service.config.GlobalParamService;
import io.mosip.registration.service.sync.MasterSyncService;
import io.mosip.registration.util.healthcheck.RegistrationSystemPropertiesChecker;
import lombok.NonNull;

import org.apache.commons.io.IOUtils;
import org.assertj.core.util.Lists;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.commons.khazana.constant.KhazanaErrorCodes;
import io.mosip.commons.khazana.exception.FileNotFoundInDestinationException;
import io.mosip.commons.khazana.spi.ObjectStoreAdapter;
import io.mosip.commons.khazana.util.EncryptionUtil;
import io.mosip.commons.packet.constants.CryptomanagerConstant;
import io.mosip.commons.packet.constants.ErrorCode;
import io.mosip.commons.packet.constants.LoggerFileConstant;
import io.mosip.commons.packet.constants.PacketManagerConstants;
import io.mosip.commons.packet.constants.PacketUtilityErrorCodes;
import io.mosip.commons.packet.dto.Document;
import io.mosip.commons.packet.dto.Packet;
import io.mosip.commons.packet.dto.packet.BiometricsType;
import io.mosip.commons.packet.dto.packet.DeviceMetaInfo;
import io.mosip.commons.packet.dto.packet.DigitalId;
import io.mosip.commons.packet.dto.packet.DocumentType;
import io.mosip.commons.packet.dto.packet.HashSequenceMetaInfo;
import io.mosip.commons.packet.dto.packet.RegistrationPacket;
import io.mosip.commons.packet.exception.NoAvailableProviderException;
import io.mosip.commons.packet.exception.ObjectStoreAdapterException;
import io.mosip.commons.packet.exception.PacketCreatorException;
import io.mosip.commons.packet.exception.PacketKeeperException;
import io.mosip.commons.packet.facade.PacketWriter;
import io.mosip.commons.packet.spi.IPacketWriter;
import io.mosip.commons.packet.util.PacketHelper;
import io.mosip.commons.packet.util.PacketManagerHelper;
import io.mosip.commons.packet.util.PacketManagerLogger;
import io.mosip.kernel.auditmanager.entity.Audit;
import io.mosip.kernel.biometrics.entities.BIR;
import io.mosip.kernel.biometrics.entities.BiometricRecord;
import io.mosip.kernel.core.exception.BaseCheckedException;
import io.mosip.kernel.core.exception.BaseUncheckedException;
import io.mosip.kernel.core.exception.ExceptionUtils;
import io.mosip.kernel.core.idgenerator.spi.RidGenerator;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.idgenerator.rid.constant.RidGeneratorPropertyConstant;
import io.mosip.registration.audit.AuditManagerService;
import io.mosip.registration.config.AppConfig;
import io.mosip.registration.constants.AuditEvent;
import io.mosip.registration.constants.AuditReferenceIdTypes;
import io.mosip.registration.constants.Components;
import io.mosip.registration.constants.RegistrationClientStatusCode;
import io.mosip.registration.constants.RegistrationConstants;
import io.mosip.registration.context.ApplicationContext;
import io.mosip.registration.context.SessionContext;
import io.mosip.registration.dao.AuditDAO;
import io.mosip.registration.dao.MachineMappingDAO;
import io.mosip.registration.dao.RegistrationDAO;
import io.mosip.registration.dto.ErrorResponseDTO;
import io.mosip.registration.dto.OSIDataDTO;
import io.mosip.registration.dto.PacketStatusDTO;
import io.mosip.registration.dto.RegistrationCenterDetailDTO;
import io.mosip.registration.dto.RegistrationDTO;
import io.mosip.registration.dto.RegistrationMetaDataDTO;
import io.mosip.registration.dto.ResponseDTO;
import io.mosip.registration.dto.SuccessResponseDTO;
import io.mosip.registration.dto.packetmanager.BiometricsDto;
import io.mosip.registration.dto.packetmanager.DocumentDto;
import io.mosip.registration.dto.packetmanager.metadata.BiometricsMetaInfoDto;
import io.mosip.registration.dto.packetmanager.metadata.DocumentMetaInfoDTO;
import io.mosip.registration.dto.schema.SchemaDto;
import io.mosip.registration.entity.Registration;
import io.mosip.registration.exception.RegBaseCheckedException;
import io.mosip.registration.exception.RegistrationExceptionConstants;
import io.mosip.registration.mdm.service.impl.MosipDeviceSpecificationFactory;
import io.mosip.registration.service.BaseService;
import io.mosip.registration.service.IdentitySchemaService;
import io.mosip.registration.service.bio.BioService;
import io.mosip.registration.service.packet.PacketHandlerService;
import io.mosip.registration.update.SoftwareUpdateHandler;
import io.mosip.registration.util.common.BIRBuilder;
import io.mosip.kernel.biometrics.constant.OtherKey;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

/**
 * The implementation class of {@link PacketHandlerService} to handle the
 * registration data to create packet out of it and save the encrypted packet
 * data in the configured local system
 * 
 * @author Balaji Sridharanha
 * @since 1.0.0
 *
 */
@Service
public class PacketHandlerServiceImpl extends BaseService implements PacketHandlerService {

	private static final Logger LOGGER = AppConfig.getLogger(PacketHandlerServiceImpl.class);
	private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");

	@Autowired
	private Environment environment;

	@Autowired
	private AuditManagerService auditFactory;

	@Autowired
	private RegistrationDAO registrationDAO;

	@Autowired
	private GlobalParamService globalParamService;

	@Autowired
	private IdentitySchemaService identitySchemaService;

	@Autowired
	private PacketWriter packetWriter;

	@Autowired
	private BIRBuilder birBuilder;

	@Autowired
	private AuditDAO auditDAO;

	@Autowired
	private SoftwareUpdateHandler softwareUpdateHandler;

	/** The machine mapping DAO. */
	@Autowired
	private MachineMappingDAO machineMappingDAO;

	@Autowired
	private BioService bioService;

	@Autowired
	private RidGenerator<String> ridGenerator;

	@Autowired
	private ClientCryptoFacade clientCryptoFacade;

	@Autowired
	private MasterSyncService masterSyncService;

	@Value("${objectstore.packet.source:REGISTRATION_CLIENT}")
	private String source;

	@Value("${packet.manager.account.name}")
	private String packetManagerAccount;

	@Value("${object.store.base.location}")
	private String baseLocation;

	@Value("${objectstore.packet.officer_biometrics_file_name}")
	private String officerBiometricsFileName;

	@Value("${objectstore.packet.supervisor_biometrics_file_name}")
	private String supervisorBiometricsFileName;

	private ObjectMapper objectMapper = new ObjectMapper();
	private static String SLASH = "/";

	@Autowired(required = false)
	@Qualifier("referenceWriterProviders")
	@Lazy
	private List<IPacketWriter> referenceWriterProviders;

	private Map<String, RegistrationPacket> registrationPacketMap = new HashMap<>();

	private static Map<String, String> categorySubpacketMapping = new HashMap<>();

	@Value("${packetmanager.zip.datetime.pattern:yyyyMMddHHmmss}")
	private String zipDatetimePattern;

	@Value("${mosip.kernel.packet.default_subpacket_name:id}")
	private String defaultSubpacketName;

	@Autowired
	private PacketManagerHelper packetManagerHelper;

	private static final String UNDERSCORE = "_";
	private static final String HASHSEQUENCE1 = "hashSequence1";
	private static final String HASHSEQUENCE2 = "hashSequence2";

	@Value("${default.provider.version:v1.0}")
	private String defaultProviderVersion;

	@Value("${packet.manager.account.name}")
	private String PACKET_MANAGER_ACCOUNT;

	@Autowired
	@Qualifier("SwiftAdapter")
	private ObjectStoreAdapter swiftAdapter;

	@Autowired
	@Qualifier("S3Adapter")
	private ObjectStoreAdapter s3Adapter;

	@Autowired
	@Qualifier("PosixAdapter")
	private ObjectStoreAdapter posixAdapter;

	@Value("${objectstore.adapter.name}")
	private String adapterName;

	@Value("${mosip.utc-datetime-pattern:yyyy-MM-dd'T'HH:mm:ss.SSS'Z'}")
	private String dateTimePattern;

	private Map<String, Object> demographics;
	private Map<String, Document> documents;
	private Map<String, BiometricRecord> biometrics;
	

	private static final String SEPARATOR = "/";
	private static final String ZIP = ".zip";
	
	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * io.mosip.registration.service.packet.PacketHandlerService#handle(io.mosip.
	 * registration.dto.RegistrationDTO)
	 */

	static {
		categorySubpacketMapping.put("pvt", "id");
		categorySubpacketMapping.put("kyc", "id");
		categorySubpacketMapping.put("none", "id,evidence,optional");
		categorySubpacketMapping.put("evidence", "evidence");
		categorySubpacketMapping.put("optional", "optional");
	}

	@Counted
	@Timed
	@Override
	public ResponseDTO handle(RegistrationDTO registrationDTO) {
		LOGGER.info("Registration Handler had been called");
		ResponseDTO responseDTO = new ResponseDTO();
		responseDTO.setErrorResponseDTOs(new ArrayList<>());
		ErrorResponseDTO errorResponseDTO = new ErrorResponseDTO();

		if (registrationDTO == null || registrationDTO.getRegistrationId() == null) {
			errorResponseDTO.setCode(REG_PACKET_CREATION_ERROR_CODE.getErrorCode());
			errorResponseDTO.setMessage(REG_PACKET_CREATION_ERROR_CODE.getErrorMessage());
			responseDTO.getErrorResponseDTOs().add(errorResponseDTO);
			return responseDTO;
		}

		if (registrationDTO.getAdditionalInfoReqId() != null) {
			registrationDTO.setAppId(registrationDTO.getAdditionalInfoReqId().split("-")[0]);
		}

		registrationDTO.setRegistrationId(registrationDTO.getAppId());

		Map<String, String> metaInfoMap = new LinkedHashMap<>();
		try {
			SchemaDto schema = identitySchemaService.getIdentitySchema(registrationDTO.getIdSchemaVersion());
			setDemographics(registrationDTO);
			setDocuments(registrationDTO, metaInfoMap);
			setBiometrics(registrationDTO, metaInfoMap);

			setOperatorBiometrics(registrationDTO.getRegistrationId(), registrationDTO.getProcessId().toUpperCase(),
					registrationDTO.getOfficerBiometrics(), officerBiometricsFileName);
			setOperatorBiometrics(registrationDTO.getRegistrationId(), registrationDTO.getProcessId().toUpperCase(),
					registrationDTO.getSupervisorBiometrics(), supervisorBiometricsFileName);

			setAudits(registrationDTO);

			setMetaInfo(registrationDTO, metaInfoMap);
			LOGGER.debug("Adding Meta info to packet manager");
			this.addMetaInfo(registrationDTO.getRegistrationId(), metaInfoMap, source.toUpperCase(),
					registrationDTO.getProcessId().toUpperCase());

			String refId = String.valueOf(ApplicationContext.map().get(RegistrationConstants.USER_CENTER_ID))
					.concat(RegistrationConstants.UNDER_SCORE)
					.concat(String.valueOf(ApplicationContext.map().get(RegistrationConstants.USER_STATION_ID)));

			LOGGER.debug("Requesting packet manager to persist packet");
			List<PacketInfo> packetInfo = this.persistPacket(registrationDTO.getRegistrationId(),
					String.valueOf(registrationDTO.getIdSchemaVersion()), schema.getSchemaJson(), source.toUpperCase(),
					registrationDTO.getProcessId().toUpperCase(), registrationDTO.getAppId(), refId, true);

			if (!CollectionUtils.isEmpty(packetInfo)) {
				registrationDTO.setPacketId(packetInfo.get(0).getId());
			}

			LOGGER.info("Saving registration info in DB and on disk.");
			registrationDAO.save(baseLocation + SLASH + packetManagerAccount + SLASH + registrationDTO.getPacketId(),
					registrationDTO);

			globalParamService.update(RegistrationConstants.AUDIT_TIMESTAMP,
					DateUtils.getUTCCurrentDateTime().toString());

			auditFactory.audit(AuditEvent.PACKET_CREATION_SUCCESS, Components.PACKET_HANDLER,
					registrationDTO.getRegistrationId(), AuditReferenceIdTypes.REGISTRATION_ID.getReferenceTypeId());

			SuccessResponseDTO successResponseDTO = new SuccessResponseDTO();
			successResponseDTO.setCode("0000");
			successResponseDTO.setMessage("Success");
			responseDTO.setSuccessResponseDTO(successResponseDTO);

		} catch (RegBaseCheckedException regBaseCheckedException) {
			LOGGER.error("Exception while creating packet ", regBaseCheckedException);

			auditFactory.audit(AuditEvent.PACKET_INTERNAL_ERROR, Components.PACKET_HANDLER,
					registrationDTO.getRegistrationId(), AuditReferenceIdTypes.REGISTRATION_ID.getReferenceTypeId());

			errorResponseDTO.setCode(regBaseCheckedException.getErrorCode());
			errorResponseDTO.setMessage(regBaseCheckedException.getErrorText());
			responseDTO.getErrorResponseDTOs().add(errorResponseDTO);
		} catch (Exception exception) {
			LOGGER.error("Exception while creating packet ", exception);

			auditFactory.audit(AuditEvent.PACKET_INTERNAL_ERROR, Components.PACKET_HANDLER,
					registrationDTO.getRegistrationId(), AuditReferenceIdTypes.REGISTRATION_ID.getReferenceTypeId());

			errorResponseDTO.setCode(exception.getMessage());
			errorResponseDTO.setMessage(exception.getMessage());
			responseDTO.getErrorResponseDTOs().add(errorResponseDTO);
		} finally {
			LOGGER.info("Finally clearing all the captured data from registration DTO");
			registrationDTO.clearRegistrationDto();
		}
		LOGGER.info(LOG_PKT_HANLDER, APPLICATION_NAME, APPLICATION_ID, "Registration Handler had been ended");
		return responseDTO;
	}

	private void setOperatorBiometrics(String registrationId, String registrationCategory,
			List<BiometricsDto> operatorBiometrics, String fileName) {
		/** Operator/officer/supervisor Biometrics */
		if (!operatorBiometrics.isEmpty()) {
			LOGGER.debug("Adding operator biometrics : {}", fileName);
			BiometricRecord biometricRecord = new BiometricRecord();
			for (BiometricsDto biometricsDto : operatorBiometrics) {
				BIR bir = birBuilder.buildBIR(biometricsDto);
				biometricRecord.getSegments().add(bir);
			}
			this.setBiometric(registrationId, fileName, biometricRecord, source.toUpperCase(),
					registrationCategory.toUpperCase());
		}
	}

	private void setMetaInfo(RegistrationDTO registrationDTO, Map<String, String> metaInfoMap)
			throws RegBaseCheckedException {

		LOGGER.debug(LOG_PKT_HANLDER, APPLICATION_NAME, APPLICATION_ID, "Adding registered devices to meta info");
		addRegisteredDevices(metaInfoMap);

		LOGGER.debug(LOG_PKT_HANLDER, APPLICATION_NAME, APPLICATION_ID, "Adding operations data to meta info");
		setOperationsData(metaInfoMap, registrationDTO);

		LOGGER.debug(LOG_PKT_HANLDER, APPLICATION_NAME, APPLICATION_ID, "Adding other info to meta info");
		setOthersMetaInfo(metaInfoMap, registrationDTO);

		setMetaData(metaInfoMap, registrationDTO);

	}

	private void setMetaData(Map<String, String> metaInfoMap, RegistrationDTO registrationDTO)
			throws RegBaseCheckedException {
		Map<String, String> metaData = new LinkedHashMap<>();
		metaData.put(PacketManagerConstants.REGISTRATIONID, registrationDTO.getRegistrationId());
		metaData.put(RegistrationConstants.PACKET_APPLICATION_ID, registrationDTO.getAppId());
		metaData.put(PacketManagerConstants.META_CREATION_DATE, LocalDateTime.now(ZoneId.of("UTC"))
				.format(DateTimeFormatter.ofPattern(RidGeneratorPropertyConstant.TIMESTAMP_FORMAT.getProperty())));
		metaData.put(PacketManagerConstants.META_CLIENT_VERSION, softwareUpdateHandler.getCurrentVersion());
		metaData.put(PacketManagerConstants.META_REGISTRATION_TYPE,
				registrationDTO.getFlowType().getCategory().toUpperCase());
		metaData.put(PacketManagerConstants.META_PRE_REGISTRATION_ID, registrationDTO.getPreRegistrationId());

		MachineMaster machineMaster = machineMappingDAO.getMachine();
		if (machineMaster == null || machineMaster.getRegCenterId() == null) {
			throwRegBaseCheckedException(RegistrationExceptionConstants.REG_PKT_INVALID_MACHINE_ID_EXCEPTION);
		} else {
			metaData.put(PacketManagerConstants.META_MACHINE_ID, machineMaster.getId());
			metaData.put(PacketManagerConstants.META_CENTER_ID, machineMaster.getRegCenterId());
			metaData.put(PacketManagerConstants.META_DONGLE_ID, machineMaster.getSerialNum());
			metaData.put(PacketManagerConstants.META_KEYINDEX, machineMaster.getKeyIndex());
		}

		metaData.put("langCodes",
				String.join(RegistrationConstants.COMMA, registrationDTO.getSelectedLanguagesByApplicant()));
		metaData.put(PacketManagerConstants.META_APPLICANT_CONSENT,
				registrationDTO.getRegistrationMetaDataDTO().getConsentOfApplicant());

		metaInfoMap.put("metaData", getJsonString(getLabelValueDTOListString(metaData)));
		metaInfoMap.put("blockListedWords", getJsonString(registrationDTO.BLOCKLISTED_CHECK));
	}

	private void setOperationsData(Map<String, String> metaInfoMap, RegistrationDTO registrationDTO)
			throws RegBaseCheckedException {

		Map<String, String> operationsDataMap = new LinkedHashMap<>();
		operationsDataMap.put(PacketManagerConstants.META_OFFICER_ID, registrationDTO.getOsiDataDTO().getOperatorID());
		operationsDataMap.put(PacketManagerConstants.META_OFFICER_BIOMETRIC_FILE,
				registrationDTO.getOfficerBiometrics().isEmpty() ? null : officerBiometricsFileName);
		operationsDataMap.put(PacketManagerConstants.META_SUPERVISOR_ID,
				registrationDTO.getOsiDataDTO().getSupervisorID());
		operationsDataMap.put(PacketManagerConstants.META_SUPERVISOR_BIOMETRIC_FILE,
				registrationDTO.getSupervisorBiometrics().isEmpty() ? null : supervisorBiometricsFileName);
		operationsDataMap.put(PacketManagerConstants.META_SUPERVISOR_PWD,
				String.valueOf(registrationDTO.getOsiDataDTO().isSuperviorAuthenticatedByPassword()));
		operationsDataMap.put(PacketManagerConstants.META_OFFICER_PWD,
				String.valueOf(registrationDTO.getOsiDataDTO().isOperatorAuthenticatedByPassword()));
		operationsDataMap.put(PacketManagerConstants.META_SUPERVISOR_PIN, null);
		operationsDataMap.put(PacketManagerConstants.META_OFFICER_PIN, null);
		operationsDataMap.put(PacketManagerConstants.META_SUPERVISOR_OTP,
				String.valueOf(registrationDTO.getOsiDataDTO().isSuperviorAuthenticatedByPIN()));
		operationsDataMap.put(PacketManagerConstants.META_OFFICER_OTP,
				String.valueOf(registrationDTO.getOsiDataDTO().isOperatorAuthenticatedByPIN()));

		metaInfoMap.put(PacketManagerConstants.META_INFO_OPERATIONS_DATA,
				getJsonString(getLabelValueDTOListString(operationsDataMap)));

	}

	private List<Map<String, String>> getLabelValueDTOListString(Map<String, String> operationsDataMap) {

		List<Map<String, String>> labelValueMap = new LinkedList<>();

		for (Entry<String, String> fieldName : operationsDataMap.entrySet()) {

			Map<String, String> map = new LinkedHashMap<>();

			map.put("label", fieldName.getKey());
			map.put("value", fieldName.getValue());

			labelValueMap.add(map);
		}

		return labelValueMap;
	}

	private void setOthersMetaInfo(Map<String, String> metaInfoMap, RegistrationDTO registrationDTO)
			throws RegBaseCheckedException {

		RegistrationCenterDetailDTO registrationCenter = SessionContext.userContext().getRegistrationCenterDetailDTO();
		if (RegistrationConstants.ENABLE
				.equalsIgnoreCase(environment.getProperty(RegistrationConstants.GPS_DEVICE_DISABLE_FLAG))) {
			metaInfoMap.put(PacketManagerConstants.META_LATITUDE, registrationCenter.getRegistrationCenterLatitude());
			metaInfoMap.put(PacketManagerConstants.META_LONGITUDE, registrationCenter.getRegistrationCenterLongitude());
		}

		Map<String, String> checkSumMap = softwareUpdateHandler.getJarChecksum();
		metaInfoMap.put("checkSum", getJsonString(checkSumMap));
		metaInfoMap.put(PacketManagerConstants.REGISTRATIONID, registrationDTO.getRegistrationId());
	}

	private void setDemographics(RegistrationDTO registrationDTO) throws RegBaseCheckedException {
		LOGGER.debug(LOG_PKT_HANLDER, APPLICATION_NAME, APPLICATION_ID, "Adding demographics to packet manager");
		Map<String, Object> demographics = registrationDTO.getDemographics();

		for (String fieldName : demographics.keySet()) {
			LOGGER.info("Adding demographics for field : {}", fieldName);
			switch (registrationDTO.getFlowType()) {
			case UPDATE:
				if (demographics.get(fieldName) != null
						&& (registrationDTO.getUpdatableFields().contains(fieldName) || fieldName.equals("UIN")))
					setField(registrationDTO.getRegistrationId(), fieldName, demographics.get(fieldName),
							registrationDTO.getProcessId().toUpperCase(), source);
				break;
			case CORRECTION:
			case LOST:
			case NEW:
				if (demographics.get(fieldName) != null)
					setField(registrationDTO.getRegistrationId(), fieldName, demographics.get(fieldName),
							registrationDTO.getProcessId().toUpperCase(), source);
				break;
			}
		}
	}

	private void setDocuments(RegistrationDTO registrationDTO, Map<String, String> metaInfoMap)
			throws RegBaseCheckedException {
		LOGGER.debug("Adding Documents to packet manager");

		List<DocumentMetaInfoDTO> documentMetaInfoDTOs = new LinkedList<>();
		for (String fieldName : registrationDTO.getDocuments().keySet()) {
			DocumentDto document = registrationDTO.getDocuments().get(fieldName);
			DocumentMetaInfoDTO documentMetaInfoDTO = new DocumentMetaInfoDTO();
			documentMetaInfoDTO.setDocumentCategory(document.getCategory());
			documentMetaInfoDTO.setDocumentName(document.getValue());
			documentMetaInfoDTO.setDocumentOwner(document.getOwner());
			documentMetaInfoDTO.setDocumentType(document.getType());
			documentMetaInfoDTO.setRefNumber(document.getRefNumber());

			documentMetaInfoDTOs.add(documentMetaInfoDTO);

			packetWriter.setDocument(registrationDTO.getRegistrationId(), fieldName, getDocument(document),
					source.toUpperCase(), registrationDTO.getProcessId().toUpperCase());
		}

		metaInfoMap.put("documents", getJsonString(documentMetaInfoDTOs));
	}

	private void setBiometrics(RegistrationDTO registrationDTO, Map<String, String> metaInfoMap)
			throws RegBaseCheckedException {
		LOGGER.debug("Adding Biometrics to packet manager started..");
		Map<String, List<BIR>> capturedBiometrics = new HashMap<>();
		Map<String, Map<String, Object>> capturedMetaInfo = new LinkedHashMap<>();
		Map<String, Map<String, Object>> exceptionMetaInfo = new LinkedHashMap<>();

		for (String key : registrationDTO.getBiometrics().keySet()) {
			String fieldId = key.split("_")[0];
			String bioAttribute = key.split("_")[1];
			BIR bir = birBuilder.buildBIR(registrationDTO.getBiometrics().get(key));
			if (!capturedBiometrics.containsKey(fieldId)) {
				capturedBiometrics.put(fieldId, new ArrayList<>());
			}
			capturedBiometrics.get(fieldId).add(bir);
			if (!capturedMetaInfo.containsKey(fieldId)) {
				capturedMetaInfo.put(fieldId, new HashMap<>());
			}
			capturedMetaInfo.get(fieldId).put(bioAttribute,
					new BiometricsMetaInfoDto(registrationDTO.getBiometrics().get(key).getNumOfRetries(),
							registrationDTO.getBiometrics().get(key).isForceCaptured(), bir.getBdbInfo().getIndex()));
		}

		for (String key : registrationDTO.getBiometricExceptions().keySet()) {
			String fieldId = key.split("_")[0];
			String bioAttribute = key.split("_")[1];
			BIR bir = birBuilder.buildBIR(new BiometricsDto(bioAttribute, null, 0));
			capturedBiometrics.getOrDefault(fieldId, new ArrayList<>()).add(bir);
			exceptionMetaInfo.getOrDefault(fieldId, new HashMap<>()).put(bioAttribute,
					registrationDTO.getBiometricExceptions().get(key));
		}

		capturedBiometrics.keySet().forEach(fieldId -> {
			BiometricRecord biometricRecord = new BiometricRecord();
			biometricRecord.setOthers(new HashMap<>());
			biometricRecord.getOthers().put(OtherKey.CONFIGURED, String.join(",",
					registrationDTO.CONFIGURED_BIOATTRIBUTES.getOrDefault(fieldId, Collections.EMPTY_LIST)));
			biometricRecord.setSegments(capturedBiometrics.get(fieldId));
			LOGGER.debug("Adding biometric to packet manager for field : {}", fieldId);
			packetWriter.setBiometric(registrationDTO.getRegistrationId(), fieldId, biometricRecord, source.toUpperCase(),
					registrationDTO.getProcessId().toUpperCase());
		});

		metaInfoMap.put("biometrics", getJsonString(capturedMetaInfo));
		metaInfoMap.put("exceptionBiometrics", getJsonString(exceptionMetaInfo));
	}

	private void setAudits(RegistrationDTO registrationDTO) {
		String auditTimestamp = getGlobalConfigValueOf(RegistrationConstants.AUDIT_TIMESTAMP);
		List<Audit> audits = auditDAO.getAudits(registrationDTO.getRegistrationId(), auditTimestamp);

		List<Map<String, String>> auditList = new LinkedList<>();

		for (Audit audit : audits) {
			Map<String, String> auditMap = new LinkedHashMap<>();
			auditMap.put("uuid", audit.getUuid());
			auditMap.put("createdAt", audit.getCreatedAt().format(formatter));
			auditMap.put("eventId", audit.getEventId());
			auditMap.put("eventName", audit.getEventName());
			auditMap.put("eventType", audit.getEventType());
			auditMap.put("hostName", audit.getHostName());
			auditMap.put("hostIp", audit.getHostIp());
			auditMap.put("applicationId", audit.getApplicationId());
			auditMap.put("applicationName", audit.getApplicationName());
			auditMap.put("sessionUserId", audit.getSessionUserId());
			auditMap.put("sessionUserName", audit.getSessionUserName());
			auditMap.put("id", audit.getId());
			auditMap.put("idType", audit.getIdType());
			auditMap.put("createdBy", audit.getCreatedBy());
			auditMap.put("moduleName", audit.getModuleName());
			auditMap.put("moduleId", audit.getModuleId());
			auditMap.put("description", audit.getDescription());
			auditMap.put("actionTimeStamp", audit.getActionTimeStamp().format(formatter));
			auditList.add(auditMap);
		}
		Assert.notEmpty(auditList, "Audit list is empty for the current registration");
		this.addAudits(registrationDTO.getRegistrationId(), auditList, source.toUpperCase(),
				registrationDTO.getProcessId());
	}

	private void addRegisteredDevices(Map<String, String> metaInfoMap) throws RegBaseCheckedException {
		List<DeviceMetaInfo> capturedRegisteredDevices = new ArrayList<DeviceMetaInfo>();
		MosipDeviceSpecificationFactory.getDeviceRegistryInfo().forEach((deviceName, device) -> {
			DeviceMetaInfo registerdDevice = new DeviceMetaInfo();
			registerdDevice.setDeviceServiceVersion(device.getSerialVersion());
			registerdDevice.setDeviceCode(device.getDeviceCode());
			DigitalId digitalId = new DigitalId();
			digitalId.setDateTime(device.getTimestamp());
			digitalId.setDeviceProvider(device.getDeviceProviderName());
			digitalId.setDeviceProviderId(device.getDeviceProviderId());
			digitalId.setMake(device.getDeviceMake());
			digitalId.setModel(device.getDeviceModel());
			digitalId.setSerialNo(device.getSerialNumber());
			digitalId.setDeviceSubType(device.getDeviceSubType());
			digitalId.setType(device.getDeviceType());
			registerdDevice.setDigitalId(digitalId);
			capturedRegisteredDevices.add(registerdDevice);
		});

		metaInfoMap.put("capturedRegisteredDevices", getJsonString(capturedRegisteredDevices));
	}

	private void setField(String registrationId, String fieldName, Object value, String process, String source)
			throws RegBaseCheckedException {
		LOGGER.debug("Adding demographics to packet manager for field : {}", fieldName);
		packetWriter.setField(registrationId, fieldName, getValueAsString(value), source.toUpperCase(), process.toUpperCase());
	}

	private String getValueAsString(Object value) throws RegBaseCheckedException {
		if (value instanceof String) {
			return (String) value;
		} else {
			return getJsonString(value);
		}

	}

	private String getJsonString(Object object) throws RegBaseCheckedException {
		try {
			return objectMapper.writeValueAsString(object);
		} catch (IOException ioException) {
			throw new RegBaseCheckedException(
					RegistrationExceptionConstants.REG_JSON_PROCESSING_EXCEPTION.getErrorCode(),
					RegistrationExceptionConstants.REG_JSON_PROCESSING_EXCEPTION.getErrorMessage());
		}
	}

	private Document getDocument(DocumentDto documentDto) {
		Document document = new Document();

		document.setDocument(documentDto.getDocument());
		document.setFormat(documentDto.getFormat());
		document.setType(documentDto.getType());
		document.setValue(documentDto.getValue());
		document.setRefNumber(documentDto.getRefNumber());
		return document;
	}

	@Override
	public List<Registration> getAllRegistrations() {
		return registrationDAO.getAllRegistrations();
	}

	@Override
	public List<PacketStatusDTO> getAllPackets() {
		LOGGER.info("Fetching all the packets that are registered");
		List<PacketStatusDTO> packets = new ArrayList<>();
		List<Registration> registeredPackets = registrationDAO.getAllRegistrations();
		for (Registration registeredPacket : registeredPackets) {
			if (!registeredPacket.getClientStatusCode()
					.equalsIgnoreCase(RegistrationClientStatusCode.CREATED.getCode())) {
				packets.add(preparePacketStatusDto(registeredPacket));
			}
		}
		return packets;
	}

	@Counted
	@Timed
	@Override
	public RegistrationDTO startRegistration(String id, @NonNull String processId) throws RegBaseCheckedException {
		// Pre-check conditions, throws exception if preconditions are not met
		proceedWithRegistration();

		RegistrationDTO registrationDTO = new RegistrationDTO();
		// set id-schema version to be followed for this registration
		registrationDTO.setIdSchemaVersion(identitySchemaService.getLatestEffectiveSchemaVersion());
		ProcessSpecDto processSpecDto = identitySchemaService.getProcessSpecDto(processId,
				registrationDTO.getIdSchemaVersion());
		registrationDTO.setProcessId(processSpecDto.getId());
		registrationDTO.setFlowType(FlowType.valueOf(processSpecDto.getFlow()));

		// Create object for OSIData DTO
		registrationDTO.setOsiDataDTO(new OSIDataDTO());
		// by default setting the maker ID
		registrationDTO.getOsiDataDTO().setOperatorID(SessionContext.userId());

		// Create RegistrationMetaData DTO & set default values in it
		RegistrationMetaDataDTO registrationMetaDataDTO = new RegistrationMetaDataDTO();
		registrationDTO.setRegistrationMetaDataDTO(registrationMetaDataDTO);

		// set application id
//		registrationDTO.setAppId(ridGenerator.generateId(
//				(String) ApplicationContext.map().get(RegistrationConstants.USER_CENTER_ID),
//				(String) ApplicationContext.map().get(RegistrationConstants.USER_STATION_ID)));
		registrationDTO.setAppId((String) ApplicationContext.map().get(RegistrationConstants.USER_CENTER_ID)
				+ (String) ApplicationContext.map().get(RegistrationConstants.USER_STATION_ID) + gen());
		registrationDTO.setRegistrationId(registrationDTO.getAppId());

		LOGGER.info("Registration Started for ApplicationId  : {}", registrationDTO.getAppId());

		List<String> defaultFieldGroups = new ArrayList<>();
		if (processSpecDto.getAutoSelectedGroups() != null)
			defaultFieldGroups.addAll(processSpecDto.getAutoSelectedGroups());

		registrationDTO.setDefaultUpdatableFieldGroups(defaultFieldGroups);
		registrationDTO.setConfiguredBlockListedWords(masterSyncService.getAllBlockListedWords());
		return registrationDTO;
	}

	@Override
	public void createAcknowledgmentReceipt(@NonNull String packetId, byte[] content, String format)
			throws io.mosip.kernel.core.exception.IOException {
		LOGGER.debug("Starting to create Registration ack receipt : {}", packetId);
		byte[] signature = clientCryptoFacade.getClientSecurity().signData(content);
		byte[] key = clientCryptoFacade.getClientSecurity().getEncryptionPublicPart();
		FileUtils.copyToFile(new ByteArrayInputStream(content),
				Paths.get(baseLocation, packetManagerAccount, packetId.concat("_Ack.").concat(format)).toFile());
		registrationDAO.updateAckReceiptSignature(packetId, CryptoUtil.encodeToURLSafeBase64(signature));
	}

	public String getAcknowledgmentReceipt(@NonNull String packetId, @NonNull String filepath)
			throws RegBaseCheckedException, io.mosip.kernel.core.exception.IOException {
		Registration registration = registrationDAO.getRegistrationByPacketId(packetId);

		// handling backward compatibility for existing pre-LTS packets receipt
//		if (registration.getAckSignature() == null && registration.getPacketId().equals(registration.getId())) {
		try {
			LOGGER.info("As signature is empty, attempting to sign and encrypt ack receipt : {}", packetId);
			createAcknowledgmentReceipt(packetId, FileUtils.readFileToByteArray(new File(filepath)),
					RegistrationConstants.ACKNOWLEDGEMENT_FORMAT);
			registration = registrationDAO.getRegistrationByPacketId(packetId);
		} catch (io.mosip.kernel.core.exception.IOException ex) {
			LOGGER.error("Failed to sign and encrypt existing ack receipt : {}", packetId, ex);
		}
//		}
		byte[] decryptedContent2 = FileUtils.readFileToByteArray(new File(filepath));
//		byte[] decryptedContent = clientCryptoFacade.decrypt(FileUtils.readFileToByteArray(new File(filepath)));
//		boolean isSignatureValid = clientCryptoFacade.getClientSecurity().validateSignature(
//				ClientCryptoUtils.decodeBase64Data(registration.getAckSignature()), decryptedContent2);
//		if (isSignatureValid)
		return new String(decryptedContent2);

//		throw new RegBaseCheckedException(RegistrationExceptionConstants.REG_ACK_RECEIPT_READ_ERROR.getErrorCode(),
//				RegistrationExceptionConstants.REG_ACK_RECEIPT_READ_ERROR.getErrorMessage());
	}

	public int gen() {
		Random r = new Random(System.currentTimeMillis());
		return ((1 + r.nextInt(2)) * 10000 + r.nextInt(10000));
	}

	public List<PacketInfo> persistPacket(String id, String version, String schemaJson, String source, String process,
			String additionalInfoReqId, String refId, boolean offlineMode) {
		LOGGER.info(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, id,
				"persistPacket for source : " + source + " process : " + process);
		return this.persistPacket1(id, version, schemaJson, source, process, additionalInfoReqId, refId, offlineMode);
	}

	/**
	 * Get the packet writer provider instance for source and process
	 *
	 * @param source  : the source packet. Default if not provided.
	 * @param process : the process
	 * @return IPacketWriter : the provider instance
	 */
	private IPacketWriter getProvider(String source, String process) {
		IPacketWriter provider = null;
		if (referenceWriterProviders != null && !referenceWriterProviders.isEmpty()) {
			Optional<IPacketWriter> refProvider = referenceWriterProviders.stream()
					.filter(refPr -> (PacketHelper.isSourceAndProcessPresent(refPr.getClass().getName(), source,
							process, PacketHelper.Provider.WRITER)))
					.findAny();
			if (refProvider.isPresent() && refProvider.get() != null)
				provider = refProvider.get();
		}

		if (provider == null) {
			LOGGER.error(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, null,
					"No available provider found for source : " + source + " process : " + process);
			throw new NoAvailableProviderException();
		}

		return provider;
	}

	public List<PacketInfo> persistPacket1(String id, String version, String schemaJson, String source, String process,
			String additionalInfoReqId, String refId, boolean offlineMode) {
		try {
			return createPacket(id, version, schemaJson, source, process, additionalInfoReqId, refId, offlineMode);
		} catch (PacketCreatorException e) {
			LOGGER.error(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, id,
					ExceptionUtils.getStackTrace(e));
			throw e;
		}
	}

	private List<PacketInfo> createPacket(String id, String version, String schemaJson, String source, String process,
			String additionalInfoReqId, String refId, boolean offlineMode) throws PacketCreatorException {
		LOGGER.info(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.ID.toString(), id,
				"Started packet creation");
//		if (registrationPacketMap.get(id) == null)
//			throw new PacketCreatorException(ErrorCode.INITIALIZATION_ERROR.getErrorCode(),
//					ErrorCode.INITIALIZATION_ERROR.getErrorMessage());

		List<PacketInfo> packetInfos = new ArrayList<>();

		Map<String, List<Object>> identityProperties = loadSchemaFields(schemaJson);

		try {
			int counter = 1;
			String packetId = new StringBuilder()
					.append(StringUtils.isNotBlank(additionalInfoReqId) ? additionalInfoReqId : id).append("-")
					.append(refId).append("-").append(getcurrentTimeStamp()).toString();
			for (String subPacketName : identityProperties.keySet()) {
				LOGGER.info(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.ID.toString(), id,
						"Started Subpacket: " + subPacketName);
				List<Object> schemaFields = identityProperties.get(subPacketName);
				byte[] subpacketBytes = createSubpacket(Double.valueOf(version), schemaFields,
						defaultSubpacketName.equalsIgnoreCase(subPacketName), id, offlineMode);

				PacketInfo packetInfo = new PacketInfo();
				packetInfo.setProviderName(this.getClass().getSimpleName());
				packetInfo.setSchemaVersion(new Double(version).toString());
				if (offlineMode)
					packetInfo.setId(packetId);
				else
					packetInfo.setId(id);
				packetInfo.setRefId(refId);
				packetInfo.setSource(source);
				packetInfo.setProcess(process);
				packetInfo.setPacketName(id + UNDERSCORE + subPacketName);
				packetInfo.setCreationDate(DateUtils.getUTCCurrentDateTimeString());
				packetInfo.setProviderVersion(defaultProviderVersion);
				Packet packet = new Packet();
				packet.setPacketInfo(packetInfo);
				packet.setPacket(subpacketBytes);
				this.putPacket(packet);
				packetInfos.add(packetInfo);
				LOGGER.info(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.ID.toString(), id,
						"Completed Subpacket: " + subPacketName);

				if (counter == identityProperties.keySet().size()) {
					boolean res = this.pack(packetInfo.getId(), packetInfo.getSource(), packetInfo.getProcess(),
							packetInfo.getRefId());
					if (!res)
						this.deletePacket(id, source, process);
				}

				counter++;
			}

		} catch (Exception e) {
			LOGGER.error(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.ID.toString(), id,
					"Exception occured. Deleting the packet.");
			this.deletePacket(id, source, process);
			throw new PacketCreatorException(ErrorCode.PKT_ZIP_ERROR.getErrorCode(),
					ErrorCode.PKT_ZIP_ERROR.getErrorMessage().concat(ExceptionUtils.getStackTrace(e)));
		} finally {
			this.registrationPacketMap.remove(id);
			LOGGER.debug(
					"registrationPacketMap size ====================================> " + registrationPacketMap.size());
		}
		LOGGER.info(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.ID.toString(), id,
				"Exiting packet creation");
		return packetInfos;
	}

	private Map<String, List<Object>> loadSchemaFields(String schemaJson) throws PacketCreatorException {
		Map<String, List<Object>> packetBasedMap = new HashMap<String, List<Object>>();

		try {
			JSONObject schema = new JSONObject(schemaJson);
			schema = schema.getJSONObject(PacketManagerConstants.PROPERTIES);
			schema = schema.getJSONObject(PacketManagerConstants.IDENTITY);
			schema = schema.getJSONObject(PacketManagerConstants.PROPERTIES);

			JSONArray fieldNames = schema.names();
			for (int i = 0; i < fieldNames.length(); i++) {
				String fieldName = fieldNames.getString(i);
				JSONObject fieldDetail = schema.getJSONObject(fieldName);
				String fieldCategory = fieldDetail.has(PacketManagerConstants.SCHEMA_CATEGORY)
						? fieldDetail.getString(PacketManagerConstants.SCHEMA_CATEGORY)
						: "none";
				String packets = categorySubpacketMapping.get(fieldCategory.toLowerCase());

				String[] packetNames = packets.split(",");
				for (String packetName : packetNames) {
					if (!packetBasedMap.containsKey(packetName)) {
						packetBasedMap.put(packetName, new ArrayList<Object>());
					}

					Map<String, String> attributes = new HashMap<>();
					attributes.put(PacketManagerConstants.SCHEMA_ID, fieldName);
					attributes.put(PacketManagerConstants.SCHEMA_TYPE,
							fieldDetail.has(PacketManagerConstants.SCHEMA_REF)
									? fieldDetail.getString(PacketManagerConstants.SCHEMA_REF)
									: fieldDetail.getString(PacketManagerConstants.SCHEMA_TYPE));
					packetBasedMap.get(packetName).add(attributes);
				}
			}
		} catch (JSONException e) {
			throw new PacketCreatorException(ErrorCode.JSON_PARSE_ERROR.getErrorCode(),
					ErrorCode.JSON_PARSE_ERROR.getErrorMessage().concat(ExceptionUtils.getStackTrace(e)));
		}
		return packetBasedMap;
	}

	private String getcurrentTimeStamp() {
		DateTimeFormatter format = DateTimeFormatter.ofPattern(zipDatetimePattern);
		return LocalDateTime.now(ZoneId.of("UTC")).format(format);
	}

	private byte[] createSubpacket(double version, List<Object> schemaFields, boolean isDefault, String id,
			boolean offlineMode) throws PacketCreatorException {
		RegistrationPacket registrationPacket = registrationPacketMap.get(id);
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try (ZipOutputStream subpacketZip = new ZipOutputStream(new BufferedOutputStream(out))) {
			LOGGER.info(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.ID.toString(), id,
					"Identified fields >>> " + schemaFields.size());
			Map<String, Object> identity = new HashMap<String, Object>();
			Map<String, HashSequenceMetaInfo> hashSequences = new HashMap<>();

			identity.put(PacketManagerConstants.IDSCHEMA_VERSION, version);
			registrationPacket.getMetaData().put(PacketManagerConstants.REGISTRATIONID, id);
			registrationPacket.getMetaData().put(PacketManagerConstants.META_CREATION_DATE,
					registrationPacket.getCreationDate());

			for (Object obj : schemaFields) {
				Map<String, Object> field = (Map<String, Object>) obj;
				String fieldName = (String) field.get(PacketManagerConstants.SCHEMA_ID);
				LOGGER.info(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.ID.toString(), id,
						"Adding field : " + fieldName);
				switch ((String) field.get(PacketManagerConstants.SCHEMA_TYPE)) {
				case PacketManagerConstants.BIOMETRICS_TYPE:
					if (registrationPacket.getBiometrics().get(fieldName) != null)
						addBiometricDetailsToZip(registrationPacket, fieldName, identity, subpacketZip, hashSequences,
								offlineMode);
					break;
				case PacketManagerConstants.DOCUMENTS_TYPE:
					if (registrationPacket.getDocuments().get(fieldName) != null)
						addDocumentDetailsToZip(registrationPacket, fieldName, identity, subpacketZip, hashSequences,
								offlineMode);
					break;
				default:
					if (registrationPacket.getDemographics().get(fieldName) != null)
						identity.put(fieldName, registrationPacket.getDemographics().get(fieldName));
					break;
				}
			}

			byte[] identityBytes = getIdentity(identity).getBytes();
			addEntryToZip(registrationPacket, PacketManagerConstants.IDENTITY_FILENAME_WITH_EXT, identityBytes,
					subpacketZip);
			addHashSequenceWithSource(PacketManagerConstants.DEMOGRAPHIC_SEQ, PacketManagerConstants.IDENTITY_FILENAME,
					identityBytes, hashSequences);
			// addOtherFilesToZip(registrationPacket, isDefault, subpacketZip,
			// hashSequences, offlineMode);

		} catch (JsonProcessingException e) {
			throw new PacketCreatorException(ErrorCode.OBJECT_TO_JSON_ERROR.getErrorCode(),
					ErrorCode.BIR_TO_XML_ERROR.getErrorMessage().concat(ExceptionUtils.getStackTrace(e)));
		} catch (IOException e) {
			throw new PacketCreatorException(ErrorCode.PKT_ZIP_ERROR.getErrorCode(),
					ErrorCode.PKT_ZIP_ERROR.getErrorMessage().concat(ExceptionUtils.getStackTrace(e)));
		}
		return out.toByteArray();
	}

	private void addDocumentDetailsToZip(RegistrationPacket registrationPacket, String fieldName,
			Map<String, Object> identity, ZipOutputStream zipOutputStream,
			Map<String, HashSequenceMetaInfo> hashSequences, boolean offlineMode) throws PacketCreatorException {
		Document document = registrationPacket.getDocuments().get(fieldName);
//filename without extension must be set as value in ID.json
		identity.put(fieldName,
				new DocumentType(fieldName, document.getType(), document.getFormat(), document.getRefNumber()));
		String fileName = String.format("%s.%s", fieldName, document.getFormat());
		addEntryToZip(registrationPacket, fileName, document.getDocument(), zipOutputStream);
		registrationPacket.getMetaData().put(fieldName, document.getType());

		addHashSequenceWithSource(PacketManagerConstants.DEMOGRAPHIC_SEQ, fieldName, document.getDocument(),
				hashSequences);
	}

	private void addBiometricDetailsToZip(RegistrationPacket registrationPacket, String fieldName,
			Map<String, Object> identity, ZipOutputStream zipOutputStream,
			Map<String, HashSequenceMetaInfo> hashSequences, boolean offlineMode) throws PacketCreatorException {
		BiometricRecord birType = registrationPacket.getBiometrics().get(fieldName);
		if (birType != null && birType.getSegments() != null && !birType.getSegments().isEmpty()) {

			byte[] xmlBytes;
			try {
				xmlBytes = packetManagerHelper.getXMLData(birType, offlineMode);
			} catch (Exception e) {
				throw new PacketCreatorException(ErrorCode.BIR_TO_XML_ERROR.getErrorCode(),
						ErrorCode.BIR_TO_XML_ERROR.getErrorMessage().concat(ExceptionUtils.getStackTrace(e)));
			}

			addEntryToZip(registrationPacket, String.format(PacketManagerConstants.CBEFF_FILENAME_WITH_EXT, fieldName),
					xmlBytes, zipOutputStream);
			identity.put(fieldName,
					new BiometricsType(PacketManagerConstants.CBEFF_FILE_FORMAT, PacketManagerConstants.CBEFF_VERSION,
							String.format(PacketManagerConstants.CBEFF_FILENAME, fieldName)));
			addHashSequenceWithSource(PacketManagerConstants.BIOMETRIC_SEQ,
					String.format(PacketManagerConstants.CBEFF_FILENAME, fieldName), xmlBytes, hashSequences);
		}
	}

	private void addHashSequenceWithSource(String sequenceType, String name, byte[] bytes,
			Map<String, HashSequenceMetaInfo> hashSequences) {
		if (!hashSequences.containsKey(sequenceType))
			hashSequences.put(sequenceType, new HashSequenceMetaInfo(sequenceType));

		hashSequences.get(sequenceType).addHashSource(name, bytes);
	}

	private void addOtherFilesToZip(RegistrationPacket registrationPacket, boolean isDefault,
			ZipOutputStream zipOutputStream, Map<String, HashSequenceMetaInfo> hashSequences, boolean offlineMode)
			throws JsonProcessingException, PacketCreatorException, IOException, NoSuchAlgorithmException {

		if (isDefault) {
			addOperationsBiometricsToZip(registrationPacket, PacketManagerConstants.OFFICER, zipOutputStream,
					hashSequences, offlineMode);
			addOperationsBiometricsToZip(registrationPacket, PacketManagerConstants.SUPERVISOR, zipOutputStream,
					hashSequences, offlineMode);

//			if (registrationPacket.getAudits() == null || registrationPacket.getAudits().isEmpty())
//				throw new PacketCreatorException(ErrorCode.AUDITS_REQUIRED.getErrorCode(),
//						ErrorCode.AUDITS_REQUIRED.getErrorMessage());
//
//			byte[] auditBytes = JsonUtils.javaObjectToJsonString(registrationPacket.getAudits()).getBytes();
//			addEntryToZip(registrationPacket, PacketManagerConstants.AUDIT_FILENAME_WITH_EXT, auditBytes,
//					zipOutputStream);
//			addHashSequenceWithSource(PacketManagerConstants.OPERATIONS_SEQ, PacketManagerConstants.AUDIT_FILENAME,
//					auditBytes, hashSequences);

			HashSequenceMetaInfo hashSequenceMetaInfo = hashSequences.get(PacketManagerConstants.OPERATIONS_SEQ);
			addEntryToZip(
					registrationPacket, PacketManagerConstants.PACKET_OPER_HASH_FILENAME, PacketManagerHelper
							.generateHash(hashSequenceMetaInfo.getValue(), hashSequenceMetaInfo.getHashSource()),
					zipOutputStream);

			registrationPacket.getMetaData().put(HASHSEQUENCE2, Lists.newArrayList(hashSequenceMetaInfo));
		}

		addPacketDataHash(registrationPacket, hashSequences, zipOutputStream);
		addEntryToZip(registrationPacket, PacketManagerConstants.PACKET_META_FILENAME,
				getIdentity(registrationPacket.getMetaData()).getBytes(), zipOutputStream);
	}

	private void addPacketDataHash(RegistrationPacket registrationPacket,
			Map<String, HashSequenceMetaInfo> hashSequences, ZipOutputStream zipOutputStream)
			throws PacketCreatorException, IOException, NoSuchAlgorithmException {

		LinkedList<String> sequence = new LinkedList<String>();
		List<HashSequenceMetaInfo> hashSequenceMetaInfos = new ArrayList<>();
		Map<String, byte[]> data = new HashMap<>();
		if (hashSequences.containsKey(PacketManagerConstants.BIOMETRIC_SEQ)) {
			sequence.addAll(hashSequences.get(PacketManagerConstants.BIOMETRIC_SEQ).getValue());
			data.putAll(hashSequences.get(PacketManagerConstants.BIOMETRIC_SEQ).getHashSource());
			hashSequenceMetaInfos.add(hashSequences.get(PacketManagerConstants.BIOMETRIC_SEQ));
		}
		if (hashSequences.containsKey(PacketManagerConstants.DEMOGRAPHIC_SEQ)) {
			sequence.addAll(hashSequences.get(PacketManagerConstants.DEMOGRAPHIC_SEQ).getValue());
			data.putAll(hashSequences.get(PacketManagerConstants.DEMOGRAPHIC_SEQ).getHashSource());
			hashSequenceMetaInfos.add(hashSequences.get(PacketManagerConstants.DEMOGRAPHIC_SEQ));
		}
		if (hashSequenceMetaInfos.size() > 0)
			registrationPacket.getMetaData().put(HASHSEQUENCE1, hashSequenceMetaInfos);

		addEntryToZip(registrationPacket, PacketManagerConstants.PACKET_DATA_HASH_FILENAME,
				PacketManagerHelper.generateHash(sequence, data), zipOutputStream);
	}

	private void addEntryToZip(RegistrationPacket registrationPacket, String fileName, byte[] data,
			ZipOutputStream zipOutputStream) throws PacketCreatorException {
		LOGGER.info(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.ID.toString(),
				registrationPacket.getRegistrationId(), "Adding file : " + fileName);
		try {
			if (data != null) {
				ZipEntry zipEntry = new ZipEntry(fileName);
				zipOutputStream.putNextEntry(zipEntry);
				zipOutputStream.write(data);
			}
		} catch (IOException e) {
			throw new PacketCreatorException(ErrorCode.ADD_ZIP_ENTRY_ERROR.getErrorCode(),
					ErrorCode.ADD_ZIP_ENTRY_ERROR.getErrorMessage().concat(ExceptionUtils.getStackTrace(e)));
		}
	}

	private void addOperationsBiometricsToZip(RegistrationPacket registrationPacket, String operationType,
			ZipOutputStream zipOutputStream, Map<String, HashSequenceMetaInfo> hashSequences, boolean offlineMode)
			throws PacketCreatorException {

		BiometricRecord biometrics = registrationPacket.getBiometrics().get(operationType);

		if (biometrics != null && biometrics.getSegments() != null && !biometrics.getSegments().isEmpty()) {
			byte[] xmlBytes;
			try {
				xmlBytes = packetManagerHelper.getXMLData(biometrics, offlineMode);
			} catch (Exception e) {
				throw new PacketCreatorException(ErrorCode.BIR_TO_XML_ERROR.getErrorCode(),
						ErrorCode.BIR_TO_XML_ERROR.getErrorMessage().concat(ExceptionUtils.getStackTrace(e)));
			}

			if (xmlBytes != null) {
				String fileName = operationType + PacketManagerConstants.CBEFF_EXT;
				addEntryToZip(registrationPacket, fileName, xmlBytes, zipOutputStream);
				registrationPacket.getMetaData().put(String.format("%sBiometricFileName", operationType), fileName);
				addHashSequenceWithSource(PacketManagerConstants.OPERATIONS_SEQ, operationType, xmlBytes,
						hashSequences);
			}
		}
	}

	private String getIdentity(Object object) throws JsonProcessingException {
		return "{ \"identity\" : " + JsonUtils.javaObjectToJsonString(object) + " } ";
	}

	public PacketInfo putPacket(Packet packet) throws PacketKeeperException {
		try {
			// encrypt packet
			byte[] encryptedSubPacket = encrypt(packet.getPacketInfo().getRefId(), packet.getPacket());

			// put packet in object store
			boolean response = this.getAdapter().putObject(PACKET_MANAGER_ACCOUNT, packet.getPacketInfo().getId(),
					packet.getPacketInfo().getSource(), packet.getPacketInfo().getProcess(),
					packet.getPacketInfo().getPacketName(), new ByteArrayInputStream(encryptedSubPacket));

			if (response) {
				PacketInfo packetInfo = packet.getPacketInfo();
				// sign encrypted packet
//				packetInfo.setSignature(CryptoUtil.encodeToURLSafeBase64(getCryptoService().sign(packet.getPacket())));
				// generate encrypted packet hash
				packetInfo.setEncryptedHash(
						CryptoUtil.encodeToURLSafeBase64(HMACUtils2.generateHash(encryptedSubPacket)));
				Map<String, Object> metaMap = PacketManagerHelper.getMetaMap(packetInfo);
				metaMap = this.getAdapter().addObjectMetaData(PACKET_MANAGER_ACCOUNT, packet.getPacketInfo().getId(),
						packet.getPacketInfo().getSource(), packet.getPacketInfo().getProcess(),
						packet.getPacketInfo().getPacketName(), metaMap);
				return PacketManagerHelper.getPacketInfo(metaMap);
			} else
				throw new PacketKeeperException(PacketUtilityErrorCodes.PACKET_KEEPER_PUT_ERROR.getErrorCode(),
						"Unable to store packet in object store");

		} catch (Exception e) {
			LOGGER.error(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID,
					packet.getPacketInfo().getId(), ExceptionUtils.getStackTrace(e));
			if (e instanceof BaseCheckedException) {
				BaseCheckedException ex = (BaseCheckedException) e;
				throw new PacketKeeperException(ex.getErrorCode(), ex.getMessage());
			} else if (e instanceof BaseUncheckedException) {
				BaseUncheckedException ex = (BaseUncheckedException) e;
				throw new PacketKeeperException(ex.getErrorCode(), ex.getMessage());
			}
			throw new PacketKeeperException(PacketUtilityErrorCodes.PACKET_KEEPER_PUT_ERROR.getErrorCode(),
					"Failed to persist packet in object store : " + e.getMessage(), e);
		}
	}

	public byte[] encrypt(String refId, byte[] packet) {
		String packetString = CryptoUtil.encodeToURLSafeBase64(packet);
		CryptomanagerRequestDto cryptomanagerRequestDto = new CryptomanagerRequestDto();
		cryptomanagerRequestDto.setApplicationId(APPLICATION_ID);
		cryptomanagerRequestDto.setData(packetString);
		cryptomanagerRequestDto.setReferenceId(refId);

		SecureRandom sRandom = new SecureRandom();
		byte[] nonce = new byte[CryptomanagerConstant.GCM_NONCE_LENGTH];
		byte[] aad = new byte[CryptomanagerConstant.GCM_AAD_LENGTH];
		sRandom.nextBytes(nonce);
		sRandom.nextBytes(aad);
		cryptomanagerRequestDto.setAad(CryptoUtil.encodeToURLSafeBase64(aad));
		cryptomanagerRequestDto.setSalt(CryptoUtil.encodeToURLSafeBase64(nonce));
		cryptomanagerRequestDto.setTimeStamp(DateUtils.getUTCCurrentDateTime());

		byte[] encryptedData = CryptoUtil.decodeURLSafeBase64(cryptomanagerRequestDto.getData().toString());
		return EncryptionUtil.mergeEncryptedData(encryptedData, nonce, aad);
	}

	private ObjectStoreAdapter getAdapter() {
		if (adapterName.equalsIgnoreCase(swiftAdapter.getClass().getSimpleName()))
			return swiftAdapter;
		else if (adapterName.equalsIgnoreCase(posixAdapter.getClass().getSimpleName()))
			return posixAdapter;
		else if (adapterName.equalsIgnoreCase(s3Adapter.getClass().getSimpleName()))
			return s3Adapter;
		else
			throw new ObjectStoreAdapterException();
	}

	public boolean pack(String id, String source, String process, String refId) {
		return this.pack(PACKET_MANAGER_ACCOUNT, id, source, process, refId);
	}

	public boolean deletePacket(String id, String source, String process) {
		return getAdapter().removeContainer(PACKET_MANAGER_ACCOUNT, id, source, process);
	}

	public void addMetaInfo(String id, Map<String, String> metaInfo, String source, String process) {
		LOGGER.info(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, id,
				"setMetaInfo for source : " + source + " process : " + process);
		getProvider(source, process).addMetaInfo(id, metaInfo);
	}

	public RegistrationPacket initialize(String id) {
		if (registrationPacketMap.get(id) == null) {
			RegistrationPacket registrationPacket = new RegistrationPacket(dateTimePattern);
			registrationPacket.setRegistrationId(id);
			registrationPacketMap.put(id, registrationPacket);
		}
		return registrationPacketMap.get(id);
	}

	// Demographic details Puttnig in Map
	public void setField(String id, String fieldName, String value, String source, String process) {
		LOGGER.info(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, id,
				"setField for field name : " + fieldName + " source : " + source + " process : " + process);
		this.setField(id, fieldName, value);
	}

	public void setField(String id, String fieldName, String value) {
		this.initialize(id);
		this.setField(fieldName, value);
	}

	public void setField(String fieldName, String value) {
		setFields(fieldName, value, demographics);
	}

	private void setFields(String fieldName, String value, Map finalMap) {
		try {
			if (value != null) {
				Object json = new JSONTokener(value).nextValue();
				if (json instanceof JSONObject) {
					HashMap<String, Object> hashMap = new ObjectMapper().readValue(value, HashMap.class);
					finalMap.putIfAbsent(fieldName, hashMap);
				} else if (json instanceof JSONArray) {
					List jsonList = new ArrayList<>();
					JSONArray jsonArray = new JSONArray(value);
					for (int i = 0; i < jsonArray.length(); i++) {
						Object obj = jsonArray.get(i);
						HashMap<String, Object> hashMap = new ObjectMapper().readValue(obj.toString(), HashMap.class);
						jsonList.add(hashMap);
					}
					finalMap.putIfAbsent(fieldName, jsonList);
				} else
					finalMap.putIfAbsent(fieldName, value);
			} else
				finalMap.putIfAbsent(fieldName, value);
		} catch (Exception e) {
			LOGGER.error("Exception while setting field " + ExceptionUtils.getStackTrace(e));
		}
	}

	public void setFields(Map<String, String> fields) {
		fields.entrySet().forEach(entry -> {
			setFields(entry.getKey(), entry.getValue(), demographics);
		});
	}

	// Documents details Puttnig in Map
	public void setDocument(String id, String documentName, Document document, String source, String process) {
		LOGGER.info(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, id,
				"setDocument for field name : " + documentName + " source : " + source + " process : " + process);
		this.getProvider(source, process);
		this.setDocument(id, documentName, document);
	}

	public void setDocument(String id, String fieldName, Document value) {
		this.initialize(id);
		this.setDocumentField(fieldName, value);
	}

	public void setDocumentField(String fieldName, Document dto) {
		documents.put(fieldName, dto);
	}

	// Bio metric details Puttnig in Map
	public void setBiometric(String id, String fieldName, BiometricRecord biometricRecord, String source,
			String process) {
		LOGGER.info(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, id,
				"setBiometric for field name : " + fieldName + " source : " + source + " process : " + process);
		this.getProvider(source, process);
		this.setBiometric(id, fieldName, biometricRecord);
	}

	public void setBiometric(String id, String fieldName, BiometricRecord value) {
		this.initialize(id);
		this.setBiometricField(fieldName, value);
	}

	public void setBiometricField(String fieldName, BiometricRecord value) {
		this.biometrics.put(fieldName, value);
	}

	public void addAudits(String id, List<Map<String, String>> audits, String source, String process) {
		LOGGER.info(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, id,
				"setAudits for source : " + source + " process : " + process);
		this.getProvider(source, process);
		this.addAudits(id, audits);
	}

	public void addAudits(String id, List<Map<String, String>> auditList) {
		this.initialize(id);
		this.setAudits(auditList);
	}

	public void setAudits(List<Map<String, String>> audits) {
		audits.addAll(audits);
	}

	public boolean pack(String account, String container, String source, String process, String refId) {
		try {
			File accountLoc = new File(baseLocation + SEPARATOR + account);
			if (!accountLoc.exists())
				return false;
			File containerZip = new File(accountLoc.getPath() + SEPARATOR + container + ZIP);
			if (!containerZip.exists())
				throw new FileNotFoundInDestinationException(
						KhazanaErrorCodes.CONTAINER_NOT_PRESENT_IN_DESTINATION.getErrorCode(),
						KhazanaErrorCodes.CONTAINER_NOT_PRESENT_IN_DESTINATION.getErrorMessage());

			InputStream ios = new FileInputStream(containerZip);
			byte[] encryptedPacket = this.encrypt(refId, IOUtils.toByteArray(ios));
			FileUtils.copyToFile(new ByteArrayInputStream(encryptedPacket), containerZip);
			return encryptedPacket != null;
		} catch (Exception e) {
			LOGGER.error("exception occured while packing.", e);
			return false;
		}
	}
}
