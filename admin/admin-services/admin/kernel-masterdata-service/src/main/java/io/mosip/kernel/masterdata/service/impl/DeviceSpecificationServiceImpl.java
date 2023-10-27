package io.mosip.kernel.masterdata.service.impl;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;

import io.mosip.kernel.masterdata.dto.response.FilterResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Sort.Direction;
import org.springframework.stereotype.Service;

import io.mosip.kernel.core.dataaccess.exception.DataAccessLayerException;
import io.mosip.kernel.core.util.EmptyCheckUtils;
import io.mosip.kernel.masterdata.constant.DeviceSpecificationErrorCode;
import io.mosip.kernel.masterdata.constant.MasterDataConstant;
import io.mosip.kernel.masterdata.dto.DeviceSpecificationDto;
import io.mosip.kernel.masterdata.dto.DeviceSpecificationPutDto;
import io.mosip.kernel.masterdata.dto.DeviceTypeDto;
import io.mosip.kernel.masterdata.dto.FilterData;
import io.mosip.kernel.masterdata.dto.SearchDtoWithoutLangCode;
import io.mosip.kernel.masterdata.dto.getresponse.PageDto;
import io.mosip.kernel.masterdata.dto.getresponse.StatusResponseDto;
import io.mosip.kernel.masterdata.dto.getresponse.extn.DeviceSpecificationExtnDto;
import io.mosip.kernel.masterdata.dto.postresponse.IdResponseDto;
import io.mosip.kernel.masterdata.dto.request.FilterDto;
import io.mosip.kernel.masterdata.dto.request.FilterValueDto;
import io.mosip.kernel.masterdata.dto.request.Pagination;
import io.mosip.kernel.masterdata.dto.request.SearchFilter;
import io.mosip.kernel.masterdata.dto.request.SearchSort;
import io.mosip.kernel.masterdata.dto.response.ColumnCodeValue;
import io.mosip.kernel.masterdata.dto.response.FilterResponseCodeDto;
import io.mosip.kernel.masterdata.dto.response.PageResponseDto;
import io.mosip.kernel.masterdata.entity.Device;
import io.mosip.kernel.masterdata.entity.DeviceSpecification;
import io.mosip.kernel.masterdata.entity.DeviceType;
import io.mosip.kernel.masterdata.entity.id.IdAndLanguageCodeID;
import io.mosip.kernel.masterdata.exception.DataNotFoundException;
import io.mosip.kernel.masterdata.exception.MasterDataServiceException;
import io.mosip.kernel.masterdata.exception.RequestException;
import io.mosip.kernel.masterdata.repository.DeviceRepository;
import io.mosip.kernel.masterdata.repository.DeviceSpecificationRepository;
import io.mosip.kernel.masterdata.service.DeviceSpecificationService;
import io.mosip.kernel.masterdata.utils.AuditUtil;
import io.mosip.kernel.masterdata.utils.DeviceUtils;
import io.mosip.kernel.masterdata.utils.ExceptionUtils;
import io.mosip.kernel.masterdata.utils.MapperUtils;
import io.mosip.kernel.masterdata.utils.MasterDataFilterHelper;
import io.mosip.kernel.masterdata.utils.MasterdataCreationUtil;
import io.mosip.kernel.masterdata.utils.MasterdataSearchHelper;
import io.mosip.kernel.masterdata.utils.MetaDataUtils;
import io.mosip.kernel.masterdata.utils.OptionalFilter;
import io.mosip.kernel.masterdata.utils.PageUtils;
import io.mosip.kernel.masterdata.validator.FilterColumnValidator;
import io.mosip.kernel.masterdata.validator.FilterTypeEnum;
import io.mosip.kernel.masterdata.validator.FilterTypeValidator;

/**
 * Service class has methods to save and fetch DeviceSpecification Details
 * 
 * @author Megha Tanga
 * @author Uday
 * @since 1.0.0
 *
 */
/**
 * @author M1046571
 *
 */
@Service
public class DeviceSpecificationServiceImpl implements DeviceSpecificationService {

	@Autowired
	AuditUtil auditUtil;

	@Autowired
	DeviceSpecificationRepository deviceSpecificationRepository;

	@Autowired
	DeviceRepository deviceRepository;

	@Autowired
	MasterdataSearchHelper masterDataSearchHelper;

	@Autowired
	MasterDataFilterHelper masterDataFilterHelper;

	@Autowired
	FilterColumnValidator filterColumnValidator;

	@Autowired
	FilterTypeValidator filterValidator;

	@Autowired
	private DeviceUtils deviceUtil;

	@Autowired
	private PageUtils pageUtils;

	@Autowired
	private MasterdataCreationUtil masterdataCreationUtil;
	

	/*
	 * (non-Javadoc)
	 * 
	 * @see io.mosip.kernel.masterdata.service.DeviceSpecificationService#
	 * findDeviceSpecificationByLangugeCode(java.lang.String)
	 */
	@Override
	public List<DeviceSpecificationDto> findDeviceSpecificationByLangugeCode(String languageCode) {
		List<DeviceSpecification> deviceSpecificationList = null;
		List<DeviceSpecificationDto> deviceSpecificationDtoList = null;
		try {
			deviceSpecificationList = deviceSpecificationRepository
					.findAllDeviceSpecByIsActiveAndIsDeletedIsNullOrFalse();
		} catch (DataAccessException | DataAccessLayerException e) {
			throw new MasterDataServiceException(
					DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_DATA_FETCH_EXCEPTION.getErrorCode(),
					DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_DATA_FETCH_EXCEPTION.getErrorMessage()
							+ ExceptionUtils.parseException(e));
		}
		if (deviceSpecificationList != null && !deviceSpecificationList.isEmpty()) {
			deviceSpecificationDtoList = MapperUtils.mapAll(deviceSpecificationList, DeviceSpecificationDto.class);
			return deviceSpecificationDtoList;
		} else {
			throw new DataNotFoundException(
					DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_NOT_FOUND_EXCEPTION.getErrorCode(),
					DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_NOT_FOUND_EXCEPTION.getErrorMessage());
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see io.mosip.kernel.masterdata.service.DeviceSpecificationService#
	 * findDeviceSpecByLangCodeAndDevTypeCode(java.lang.String, java.lang.String)
	 */
	@Override
	public List<DeviceSpecificationDto> findDeviceSpecByLangCodeAndDevTypeCode(String languageCode,
			String deviceTypeCode) {
		List<DeviceSpecification> deviceSpecificationList = null;
		List<DeviceSpecificationDto> deviceSpecificationDtoList = null;
		try {
			deviceSpecificationList = deviceSpecificationRepository
					.findByDeviceTypeCodeAndIsDeletedFalseOrIsDeletedIsNull(deviceTypeCode);
		} catch (DataAccessException | DataAccessLayerException e) {
			throw new MasterDataServiceException(
					DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_DATA_FETCH_EXCEPTION.getErrorCode(),
					DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_DATA_FETCH_EXCEPTION.getErrorMessage()
							+ ExceptionUtils.parseException(e));
		}
		if (deviceSpecificationList != null && !deviceSpecificationList.isEmpty()) {
			deviceSpecificationDtoList = MapperUtils.mapAll(deviceSpecificationList, DeviceSpecificationDto.class);
			return deviceSpecificationDtoList;
		} else {
			throw new DataNotFoundException(
					DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_NOT_FOUND_EXCEPTION.getErrorCode(),
					DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_NOT_FOUND_EXCEPTION.getErrorMessage());
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see io.mosip.kernel.masterdata.service.DeviceSpecificationService#
	 * createDeviceSpecification(io.mosip.kernel.masterdata.dto.RequestDto)
	 */
	@Override
	public IdAndLanguageCodeID createDeviceSpecification(DeviceSpecificationDto deviceSpecification) {
		DeviceSpecification renDeviceSpecification = null;

		try {
			if (deviceSpecification.getId() == null || deviceSpecification.getId().isBlank()) {
				deviceSpecification.setId(generateId());
			}
			DeviceSpecification entity = MetaDataUtils.setCreateMetaData(deviceSpecification,
					DeviceSpecification.class);
			renDeviceSpecification = deviceSpecificationRepository.create(entity);
			Objects.requireNonNull(renDeviceSpecification);
		} catch (DataAccessLayerException | DataAccessException | NullPointerException | IllegalArgumentException
				| SecurityException e) {
			auditUtil.auditRequest(
					String.format(MasterDataConstant.FAILURE_CREATE, DeviceSpecification.class.getCanonicalName()),
					MasterDataConstant.AUDIT_SYSTEM,
					String.format(MasterDataConstant.FAILURE_DESC,
							DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_INSERT_EXCEPTION.getErrorCode(),
							DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_INSERT_EXCEPTION.getErrorMessage()),
					"ADM-648");
			throw new MasterDataServiceException(
					DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_INSERT_EXCEPTION.getErrorCode(),
					DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_INSERT_EXCEPTION.getErrorMessage()
							+ ExceptionUtils.parseException(e));

		}

		IdAndLanguageCodeID idAndLanguageCodeID = new IdAndLanguageCodeID();
		MapperUtils.map(renDeviceSpecification, idAndLanguageCodeID);

		return idAndLanguageCodeID;
	}
	
	private String generateId() throws DataAccessLayerException , DataAccessException{
		UUID uuid = UUID.randomUUID();
		String uniqueId = uuid.toString();
		
		List<DeviceSpecification> deviceSpecification = deviceSpecificationRepository
				.findDeviceSpecById(uniqueId);
			
		return deviceSpecification.isEmpty() ? uniqueId : generateId();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see io.mosip.kernel.masterdata.service.DeviceSpecificationService#
	 * updateDeviceSpecification(io.mosip.kernel.masterdata.dto.RequestDto)
	 */
	@Override
	public IdAndLanguageCodeID updateDeviceSpecification(DeviceSpecificationPutDto deviceSpecification) {
		IdAndLanguageCodeID idAndLanguageCodeID = new IdAndLanguageCodeID();
		try {
			List<DeviceSpecification> entities = deviceSpecificationRepository
					.findDeviceSpecById(deviceSpecification.getId());
			if (!EmptyCheckUtils.isNullEmpty(entities)) {
				/*
				 * if (!deviceSpecification.getIsActive()) { List<Device> devices =
				 * deviceRepository .findDeviceByDeviceSpecIdAndIsDeletedFalseorIsDeletedIsNull(
				 * deviceSpecification.getId()); if (!EmptyCheckUtils.isNullEmpty(devices)) {
				 * throw new RequestException(
				 * DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_UPDATE_MAPPING_EXCEPTION
				 * .getErrorCode(),
				 * DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_UPDATE_MAPPING_EXCEPTION
				 * .getErrorMessage()); }
				 * masterdataCreationUtil.updateMasterDataDeactivate(DeviceSpecification.class,
				 * deviceSpecification.getId()); }
				 */
				deviceSpecification = masterdataCreationUtil.updateMasterData(DeviceSpecification.class,
						deviceSpecification);
				MetaDataUtils.setUpdateMetaData(deviceSpecification, entities.get(0), false);
				deviceSpecificationRepository.update(entities.get(0));
				idAndLanguageCodeID.setId(entities.get(0).getId());
				idAndLanguageCodeID.setLangCode(entities.get(0).getLangCode());
			} else {
				auditUtil.auditRequest(
						String.format(MasterDataConstant.FAILURE_UPDATE, DeviceSpecification.class.getCanonicalName()),
						MasterDataConstant.AUDIT_SYSTEM,
						String.format(MasterDataConstant.FAILURE_DESC,
								DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_NOT_FOUND_EXCEPTION.getErrorCode(),
								DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_NOT_FOUND_EXCEPTION
										.getErrorMessage()),
						"ADM-649");
				throw new RequestException(
						DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_NOT_FOUND_EXCEPTION.getErrorCode(),
						DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_NOT_FOUND_EXCEPTION.getErrorMessage());
			}
		} catch (DataAccessLayerException | DataAccessException | IllegalArgumentException | IllegalAccessException
				| NoSuchFieldException | SecurityException e) {
			auditUtil.auditRequest(
					String.format(MasterDataConstant.FAILURE_UPDATE, DeviceSpecification.class.getCanonicalName()),
					MasterDataConstant.AUDIT_SYSTEM,
					String.format(MasterDataConstant.FAILURE_DESC,
							DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_UPDATE_EXCEPTION.getErrorCode(),
							DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_UPDATE_EXCEPTION.getErrorMessage()),
					"ADM-650");
			throw new MasterDataServiceException(
					DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_UPDATE_EXCEPTION.getErrorCode(),
					DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_UPDATE_EXCEPTION.getErrorMessage()
							+ ExceptionUtils.parseException(e));
		}

		return idAndLanguageCodeID;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see io.mosip.kernel.masterdata.service.DeviceSpecificationService#
	 * deleteDeviceSpecification(java.lang.String)
	 */
	@Override
	public IdResponseDto deleteDeviceSpecification(String id) {
		IdResponseDto idResponseDto = new IdResponseDto();
		try {
			List<DeviceSpecification> deviceSpecifications = deviceSpecificationRepository
					.findDeviceSpecById(id);

			if (!deviceSpecifications.isEmpty()) {
				for (DeviceSpecification deviceSpecification : deviceSpecifications) {
					List<Device> renDeviceList = deviceRepository
							.findDeviceByDeviceSpecIdAndIsDeletedFalseorIsDeletedIsNull(deviceSpecification.getId());
					if (renDeviceList.isEmpty()) {
						MetaDataUtils.setDeleteMetaData(deviceSpecification);
						deviceSpecificationRepository.update(deviceSpecification);
						idResponseDto.setId(deviceSpecification.getId());
					} else {
						throw new MasterDataServiceException(
								DeviceSpecificationErrorCode.DEVICE_DELETE_DEPENDENCY_EXCEPTION.getErrorCode(),
								DeviceSpecificationErrorCode.DEVICE_DELETE_DEPENDENCY_EXCEPTION.getErrorMessage());
					}
				}

			} else {
				throw new RequestException(
						DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_NOT_FOUND_EXCEPTION.getErrorCode(),
						DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_NOT_FOUND_EXCEPTION.getErrorMessage());
			}
		} catch (DataAccessLayerException | DataAccessException e) {
			throw new MasterDataServiceException(
					DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_DELETE_EXCEPTION.getErrorCode(),
					DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_DELETE_EXCEPTION.getErrorMessage()
							+ ExceptionUtils.parseException(e));
		}

		return idResponseDto;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see io.mosip.kernel.masterdata.service.DeviceSpecificationService#
	 * getAllDeviceSpecifications()
	 */
	@Override
	public PageDto<DeviceSpecificationExtnDto> getAllDeviceSpecifications(int pageNumber, int pageSize, String sortBy,
			String orderBy) {
		List<DeviceSpecificationExtnDto> deviceSpecs = null;
		PageDto<DeviceSpecificationExtnDto> pageDto = null;
		try {
			Page<DeviceSpecification> pageEntity = deviceSpecificationRepository
					.findAll(PageRequest.of(pageNumber, pageSize, Sort.by(Direction.fromString(orderBy), sortBy)));
			if (pageEntity != null && pageEntity.getContent() != null && !pageEntity.getContent().isEmpty()) {
				deviceSpecs = MapperUtils.mapAll(pageEntity.getContent(), DeviceSpecificationExtnDto.class);
				pageDto = new PageDto<>(pageEntity.getNumber(), pageEntity.getTotalPages(),
						pageEntity.getTotalElements(), deviceSpecs);
			} else {
				throw new DataNotFoundException(
						DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_NOT_FOUND_EXCEPTION.getErrorCode(),
						DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_NOT_FOUND_EXCEPTION.getErrorMessage());
			}
		} catch (DataAccessLayerException | DataAccessException e) {
			throw new MasterDataServiceException(
					DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_DATA_FETCH_EXCEPTION.getErrorCode(),
					DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_DATA_FETCH_EXCEPTION.getErrorMessage()
							+ ExceptionUtils.parseException(e));
		}
		return pageDto;
	}

	@Override
	public FilterResponseCodeDto deviceSpecFilterValues(FilterValueDto filterValueDto) {
		FilterResponseCodeDto filterResponseDto = new FilterResponseCodeDto();
		List<ColumnCodeValue> columnValueList = new ArrayList<>();
		filterValueDto.setLanguageCode(null); //language agnostic entity
		if (filterColumnValidator.validate(FilterDto.class, filterValueDto.getFilters(), DeviceSpecification.class)) {
			for (FilterDto filterDto : filterValueDto.getFilters()) {
				FilterResult<FilterData> filterResult = masterDataFilterHelper.filterValuesWithCode(
						DeviceSpecification.class, filterDto,
						filterValueDto,"id");
				filterResult.getFilterData().forEach(filterValue -> {
					ColumnCodeValue columnValue = new ColumnCodeValue();
					columnValue.setFieldCode(filterValue.getFieldCode());
					columnValue.setFieldID(filterDto.getColumnName());
					columnValue.setFieldValue(filterValue.getFieldValue());
					columnValueList.add(columnValue);
				});
				filterResponseDto.setTotalCount(filterResult.getTotalCount());
			}
			filterResponseDto.setFilters(columnValueList);
		}
		return filterResponseDto;
	}

	@Override
	public PageResponseDto<DeviceSpecificationExtnDto> searchDeviceSpec(SearchDtoWithoutLangCode dto) {
		PageResponseDto<DeviceSpecificationExtnDto> pageDto = new PageResponseDto<>();
		List<SearchFilter> addList = new ArrayList<>();
		List<SearchFilter> removeList = new ArrayList<>();
		List<DeviceSpecificationExtnDto> devices = null;
		List<SearchFilter> deviceCodeFilter = null;

		for (SearchFilter filter : dto.getFilters()) {
			String column = filter.getColumnName();
			if (column.equalsIgnoreCase("deviceTypeName")) {
				filter.setColumnName("name");
				if (filterValidator.validate(DeviceTypeDto.class, Arrays.asList(filter))) {
					pageUtils.validateSortField(DeviceSpecification.class, dto.getSort());
					Page<DeviceType> deviceTypes = masterDataSearchHelper.searchMasterdataWithoutLangCode(
							DeviceType.class,
							new SearchDtoWithoutLangCode(Arrays.asList(filter), Collections.emptyList(),
									new Pagination(), null),
							null);
					removeList.add(filter);
					deviceCodeFilter = buildDeviceTypeSearchFilter(deviceTypes.getContent());
					if (deviceCodeFilter.isEmpty()) {
						// throw new DataNotFoundException(
						// DeviceSpecificationErrorCode.PAGE_DATA_NOT_FOUND_EXCEPTION.getErrorCode(),
						// DeviceSpecificationErrorCode.PAGE_DATA_NOT_FOUND_EXCEPTION.getErrorMessage());
						return pageDto;
					}

				}
			}

		}
		dto.getFilters().removeAll(removeList);
		Pagination pagination = dto.getPagination();
		List<SearchSort> sort = dto.getSort();
		dto.setPagination(new Pagination(0, Integer.MAX_VALUE));
		dto.setSort(Collections.emptyList());
		if (filterValidator.validate(DeviceSpecificationExtnDto.class, dto.getFilters())) {
			OptionalFilter optionalFilter = new OptionalFilter(addList);
			OptionalFilter optionalFilterForDeviceTypeName = new OptionalFilter(deviceCodeFilter);
			Page<DeviceSpecification> page = masterDataSearchHelper.searchMasterdataWithoutLangCode(
					DeviceSpecification.class, dto,
					new OptionalFilter[] { optionalFilter, optionalFilterForDeviceTypeName });

			if (page.getContent() != null && !page.getContent().isEmpty()) {
				devices = MapperUtils.mapAll(page.getContent(), DeviceSpecificationExtnDto.class);
				setDeviceTypeName(devices);
				pageDto = pageUtils.sortPage(devices, sort, pagination);
			}

		}

		return pageDto;
	}

	private void setDeviceTypeName(List<DeviceSpecificationExtnDto> devicesSpecifications) {
		List<DeviceType> deviceTypes = deviceUtil.getDeviceTypes();
		devicesSpecifications.forEach(deviceSpec -> {
			deviceTypes.forEach(mt -> {
				if (deviceSpec.getDeviceTypeCode().equals(mt.getCode())) {
					deviceSpec.setDeviceTypeName(mt.getName());
				}
			});
		});
	}

	private List<SearchFilter> buildDeviceTypeSearchFilter(List<DeviceType> deviceTypes) {
		if (deviceTypes != null && !deviceTypes.isEmpty())
			return deviceTypes.stream().filter(Objects::nonNull).map(this::buildDeviceType)
					.collect(Collectors.toList());
		return Collections.emptyList();
	}

	private SearchFilter buildDeviceType(DeviceType deviceType) {
		SearchFilter filter = new SearchFilter();
		filter.setColumnName("deviceTypeCode");
		filter.setType(FilterTypeEnum.EQUALS.name());
		filter.setValue(deviceType.getCode());
		return filter;
	}

	@Override
	public StatusResponseDto updateDeviceSpecification(String id, boolean isActive) {
		// TODO Auto-generated method stub
		StatusResponseDto response = new StatusResponseDto();

		List<DeviceSpecification> deviceSpecifications = null;
		try {
			deviceSpecifications = deviceSpecificationRepository.findtoUpdateDeviceSpecById(id);
		} catch (DataAccessException | DataAccessLayerException accessException) {
			auditUtil.auditRequest(
					String.format(MasterDataConstant.FAILURE_UPDATE, DeviceSpecificationDto.class.getSimpleName()),
					MasterDataConstant.AUDIT_SYSTEM,
					String.format(MasterDataConstant.FAILURE_DESC,
							DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_DATA_FETCH_EXCEPTION.getErrorCode(),
							DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_DATA_FETCH_EXCEPTION.getErrorMessage()),
					"ADM-651");
			throw new MasterDataServiceException(
					DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_DATA_FETCH_EXCEPTION.getErrorCode(),
					DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_DATA_FETCH_EXCEPTION.getErrorMessage()
							+ ExceptionUtils.parseException(accessException));
		}

		if (deviceSpecifications != null && !deviceSpecifications.isEmpty()) {
			if (!isActive) {
				List<Device> devices = deviceRepository.findDeviceByDeviceSpecIdAndIsDeletedFalseorIsDeletedIsNull(id);
				if (!EmptyCheckUtils.isNullEmpty(devices)) {
					throw new RequestException(
							DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_UPDATE_MAPPING_EXCEPTION.getErrorCode(),
							DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_UPDATE_MAPPING_EXCEPTION
									.getErrorMessage());
				}
			}
			masterdataCreationUtil.updateMasterDataStatus(DeviceSpecification.class, id, isActive, "id");
		} else {
			auditUtil.auditRequest(
					String.format(MasterDataConstant.FAILURE_UPDATE, DeviceSpecificationDto.class.getSimpleName()),
					MasterDataConstant.AUDIT_SYSTEM,
					String.format(MasterDataConstant.FAILURE_DESC,
							DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_NOT_FOUND_EXCEPTION.getErrorCode(),
							DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_NOT_FOUND_EXCEPTION.getErrorMessage()),
					"ADM-652");
			throw new DataNotFoundException(
					DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_NOT_FOUND_EXCEPTION.getErrorCode(),
					DeviceSpecificationErrorCode.DEVICE_SPECIFICATION_NOT_FOUND_EXCEPTION.getErrorMessage());
		}
		response.setStatus("Status updated successfully for Device Specifications");
		return response;
	}

}
