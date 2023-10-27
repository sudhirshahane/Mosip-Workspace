package io.mosip.kernel.masterdata.service.impl;

import java.util.ArrayList;
import java.util.List;

import io.mosip.kernel.masterdata.dto.response.FilterResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Sort.Direction;
import org.springframework.stereotype.Service;

import io.mosip.kernel.core.dataaccess.exception.DataAccessLayerException;
import io.mosip.kernel.core.util.EmptyCheckUtils;
import io.mosip.kernel.masterdata.constant.MachineTypeErrorCode;
import io.mosip.kernel.masterdata.constant.MasterDataConstant;
import io.mosip.kernel.masterdata.dto.FilterData;
import io.mosip.kernel.masterdata.dto.MachineTypeDto;
import io.mosip.kernel.masterdata.dto.MachineTypePutDto;
import io.mosip.kernel.masterdata.dto.SearchDtoWithoutLangCode;
import io.mosip.kernel.masterdata.dto.getresponse.PageDto;
import io.mosip.kernel.masterdata.dto.getresponse.StatusResponseDto;
import io.mosip.kernel.masterdata.dto.getresponse.extn.MachineTypeExtnDto;
import io.mosip.kernel.masterdata.dto.request.FilterDto;
import io.mosip.kernel.masterdata.dto.request.FilterValueDto;
import io.mosip.kernel.masterdata.dto.request.SearchFilter;
import io.mosip.kernel.masterdata.dto.response.ColumnCodeValue;
import io.mosip.kernel.masterdata.dto.response.FilterResponseCodeDto;
import io.mosip.kernel.masterdata.dto.response.PageResponseDto;
import io.mosip.kernel.masterdata.entity.Machine;
import io.mosip.kernel.masterdata.entity.MachineSpecification;
import io.mosip.kernel.masterdata.entity.MachineType;
import io.mosip.kernel.masterdata.entity.id.CodeAndLanguageCodeID;
import io.mosip.kernel.masterdata.exception.DataNotFoundException;
import io.mosip.kernel.masterdata.exception.MasterDataServiceException;
import io.mosip.kernel.masterdata.exception.RequestException;
import io.mosip.kernel.masterdata.repository.MachineSpecificationRepository;
import io.mosip.kernel.masterdata.repository.MachineTypeRepository;
import io.mosip.kernel.masterdata.service.MachineTypeService;
import io.mosip.kernel.masterdata.utils.AuditUtil;
import io.mosip.kernel.masterdata.utils.ExceptionUtils;
import io.mosip.kernel.masterdata.utils.MapperUtils;
import io.mosip.kernel.masterdata.utils.MasterDataFilterHelper;
import io.mosip.kernel.masterdata.utils.MasterdataCreationUtil;
import io.mosip.kernel.masterdata.utils.MasterdataSearchHelper;
import io.mosip.kernel.masterdata.utils.MetaDataUtils;
import io.mosip.kernel.masterdata.utils.OptionalFilter;
import io.mosip.kernel.masterdata.utils.PageUtils;
import io.mosip.kernel.masterdata.validator.FilterColumnValidator;
import io.mosip.kernel.masterdata.validator.FilterTypeValidator;

/**
 * This class have methods to save a Machine Type Details
 * 
 * @author Megha Tanga
 * @since 1.0.0
 *
 */
@Service
public class MachineTypeServiceImpl implements MachineTypeService {

	/**
	 * Field to hold Machine Repository object
	 */
	@Autowired
	MachineTypeRepository machineTypeRepository;

	@Autowired
	MachineSpecificationRepository machineSpecificationRepository;

	/**
	 * Reference to {@link FilterTypeValidator}.
	 */
	@Autowired
	private FilterTypeValidator filterValidator;

	/**
	 * Referencr to {@link MasterdataSearchHelper}.
	 */
	@Autowired
	private MasterdataSearchHelper masterdataSearchHelper;

	/**
	 * Reference to {@link MasterDataFilterHelper}.
	 */
	@Autowired
	private MasterDataFilterHelper masterDataFilterHelper;

	/**
	 * Refernece to {@link FilterColumnValidator}.
	 */
	@Autowired
	private FilterColumnValidator filterColumnValidator;

	@Autowired
	private PageUtils pageUtils;

	@Autowired
	private AuditUtil auditUtil;
	
	@Autowired
	private MasterdataCreationUtil masterdataCreationUtil;


	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * io.mosip.kernel.masterdata.service.MachineTypeService#createMachineType(io.
	 * mosip.kernel.masterdata.dto.RequestDto)
	 */
	@Override
	public CodeAndLanguageCodeID createMachineType(MachineTypeDto machineType) {
		MachineType renMachineType = null;



		try {
			MachineType entity = MetaDataUtils.setCreateMetaData(machineType, MachineType.class);
			renMachineType = machineTypeRepository.create(entity);
		} catch (DataAccessLayerException | DataAccessException | IllegalArgumentException | SecurityException e) {
			auditUtil.auditRequest(
					String.format(MasterDataConstant.FAILURE_CREATE, MachineType.class.getCanonicalName()),
					MasterDataConstant.AUDIT_SYSTEM,
					String.format(MasterDataConstant.FAILURE_DESC,
							MachineTypeErrorCode.MACHINE_TYPE_INSERT_EXCEPTION.getErrorCode(),
							MachineTypeErrorCode.MACHINE_TYPE_INSERT_EXCEPTION.getErrorMessage()),
					"ADM-657");
			throw new MasterDataServiceException(MachineTypeErrorCode.MACHINE_TYPE_INSERT_EXCEPTION.getErrorCode(),
					MachineTypeErrorCode.MACHINE_TYPE_INSERT_EXCEPTION.getErrorMessage()
							+ ExceptionUtils.parseException(e));
		}

		CodeAndLanguageCodeID codeLangCodeId = new CodeAndLanguageCodeID();
		MapperUtils.map(renMachineType, codeLangCodeId);
		auditUtil.auditRequest(String.format(MasterDataConstant.SUCCESSFUL_CREATE, MachineType.class.getSimpleName()),
				MasterDataConstant.AUDIT_SYSTEM, String.format(MasterDataConstant.SUCCESSFUL_CREATE_DESC,
						MachineType.class.getSimpleName(), codeLangCodeId.getCode()),"ADM-948");
		return codeLangCodeId;
	}
	
	@Override
	public CodeAndLanguageCodeID updateMachineType(MachineTypePutDto machineTypeDto) {
		CodeAndLanguageCodeID codeAndLanguageCodeID = new CodeAndLanguageCodeID();
		MachineType updMachineType = null;
		try {
			List<MachineType> machineTypes = machineTypeRepository
					.findtoUpdateMachineTypeByCode(machineTypeDto.getCode());
			if (null != machineTypes && machineTypes.size() > 0) {
				machineTypeDto = masterdataCreationUtil.updateMasterData(MachineType.class, machineTypeDto);
				updMachineType = MetaDataUtils.setUpdateMetaData(machineTypeDto, machineTypes.get(0), false);
				machineTypeRepository.update(updMachineType);
				MapperUtils.map(updMachineType, codeAndLanguageCodeID);
			} else {
				auditUtil.auditRequest(
						String.format(MasterDataConstant.FAILURE_CREATE, MachineType.class.getCanonicalName()),
						MasterDataConstant.AUDIT_SYSTEM,
						String.format(MasterDataConstant.FAILURE_DESC,
								MachineTypeErrorCode.MACHINE_TYPE_NOT_FOUND.getErrorCode(),
								MachineTypeErrorCode.MACHINE_TYPE_NOT_FOUND.getErrorMessage()),
						"ADM-657");
				throw new RequestException(MachineTypeErrorCode.MACHINE_TYPE_NOT_FOUND.getErrorCode(),
						MachineTypeErrorCode.MACHINE_TYPE_NOT_FOUND.getErrorMessage());
			}
			 
		} catch (DataAccessLayerException | DataAccessException | IllegalArgumentException | IllegalAccessException
				| NoSuchFieldException | SecurityException e) {
			auditUtil.auditRequest(
					String.format(MasterDataConstant.FAILURE_CREATE, MachineType.class.getCanonicalName()),
					MasterDataConstant.AUDIT_SYSTEM,
					String.format(MasterDataConstant.FAILURE_DESC,
							MachineTypeErrorCode.MACHINE_TYPE_UPDATE_EXCEPTION.getErrorCode(),
							MachineTypeErrorCode.MACHINE_TYPE_UPDATE_EXCEPTION.getErrorMessage()),
					"ADM-657");
			throw new MasterDataServiceException(MachineTypeErrorCode.MACHINE_TYPE_UPDATE_EXCEPTION.getErrorCode(),
					MachineTypeErrorCode.MACHINE_TYPE_UPDATE_EXCEPTION.getErrorMessage()
							+ ExceptionUtils.parseException(e));
		}
		auditUtil.auditRequest(String.format(MasterDataConstant.SUCCESSFUL_UPDATE, MachineType.class.getSimpleName()),
				MasterDataConstant.AUDIT_SYSTEM, String.format(MasterDataConstant.SUCCESSFUL_UPDATE_DESC,
						MachineType.class.getSimpleName(), codeAndLanguageCodeID.getCode()),"ADM-949");
		return codeAndLanguageCodeID;
	}

	@Override
	public StatusResponseDto updateMachineTypeStatus(String code, boolean isActive) {
		StatusResponseDto statusResponseDto = new StatusResponseDto();
		try {
			List<MachineType> machineTypes = machineTypeRepository.findtoUpdateMachineTypeByCode(code);

			if (!EmptyCheckUtils.isNullEmpty(machineTypes)) {
				if (!isActive) {
				List<MachineSpecification> machineSpecifications = machineSpecificationRepository
							.findMachineSpecificationByMachineTypeCodeAndLangCodeAndIsDeletedFalseorIsDeletedIsNull(
							code);
				if (!EmptyCheckUtils.isNullEmpty(machineSpecifications)) {
						throw new RequestException(
								MachineTypeErrorCode.MACHINE_TYPE_UPDATE_MAPPING_EXCEPTION.getErrorCode(),
								MachineTypeErrorCode.MACHINE_TYPE_UPDATE_MAPPING_EXCEPTION.getErrorMessage());
					}
				}
				masterdataCreationUtil.updateMasterDataStatus(MachineType.class, code, isActive, "code");
				statusResponseDto.setStatus("Status updated successfully for machineType");
		} else {
			throw new RequestException(MachineTypeErrorCode.MACHINE_TYPE_NOT_FOUND.getErrorCode(),
					MachineTypeErrorCode.MACHINE_TYPE_NOT_FOUND.getErrorMessage());
		}

	} catch (DataAccessLayerException | DataAccessException | IllegalArgumentException | SecurityException e) {
			auditUtil.auditRequest(
					String.format(MasterDataConstant.FAILURE_TO_UPDATE_STATUS, MachineType.class.getCanonicalName()),
					MasterDataConstant.AUDIT_SYSTEM,
					String.format(MasterDataConstant.FAILURE_TO_UPDATE_STATUS,
							MachineTypeErrorCode.MACHINE_TYPE_UPDATE_EXCEPTION.getErrorCode(),
							MachineTypeErrorCode.MACHINE_TYPE_UPDATE_EXCEPTION.getErrorMessage()),
					"ADM-657");
			throw new MasterDataServiceException(MachineTypeErrorCode.MACHINE_TYPE_UPDATE_EXCEPTION.getErrorCode(),
					MachineTypeErrorCode.MACHINE_TYPE_UPDATE_EXCEPTION.getErrorMessage()
							+ ExceptionUtils.parseException(e));
		}
		auditUtil.auditRequest(String.format(MasterDataConstant.SUCCESSFUL_UPDATE, MachineType.class.getSimpleName()),
				MasterDataConstant.AUDIT_SYSTEM, String.format(MasterDataConstant.SUCCESSFUL_UPDATE_DESC,
						MachineType.class.getSimpleName(), code),"ADM-950");
		return statusResponseDto;
	}
	/*codeLangCodeId
	 * (non-Javadoc)
	 * 
	 * @see
	 * io.mosip.kernel.masterdata.service.MachineTypeService#getAllMachineTypes(int,
	 * int, java.lang.String, java.lang.String)
	 */
	@Override
	public PageDto<MachineTypeExtnDto> getAllMachineTypes(int pageNumber, int pageSize, String sortBy, String orderBy) {
		List<MachineTypeExtnDto> machineTypes = null;
		PageDto<MachineTypeExtnDto> machineTypesPages = null;
		try {
			Page<MachineType> pageData = machineTypeRepository
					.findAll(PageRequest.of(pageNumber, pageSize, Sort.by(Direction.fromString(orderBy), sortBy)));
			if (pageData != null && pageData.getContent() != null && !pageData.getContent().isEmpty()) {
				machineTypes = MapperUtils.mapAll(pageData.getContent(), MachineTypeExtnDto.class);
				machineTypesPages = new PageDto<>(pageData.getNumber(), pageData.getTotalPages(),
						pageData.getTotalElements(), machineTypes);
			} else {
				throw new DataNotFoundException(MachineTypeErrorCode.MACHINE_TYPE_NOT_FOUND.getErrorCode(),
						MachineTypeErrorCode.MACHINE_TYPE_NOT_FOUND.getErrorMessage());
			}
		} catch (DataAccessLayerException | DataAccessException e) {
			throw new MasterDataServiceException(MachineTypeErrorCode.MACHINE_TYPE_FETCH_EXCEPTION.getErrorCode(),
					MachineTypeErrorCode.MACHINE_TYPE_FETCH_EXCEPTION.getErrorMessage()
							+ ExceptionUtils.parseException(e));
		}
		return machineTypesPages;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * io.mosip.kernel.masterdata.service.MachineTypeService#searchMachineType(io.
	 * mosip.kernel.masterdata.dto.request.SearchDto)
	 */
	@SuppressWarnings("null")
	@Override
	public PageResponseDto<MachineTypeExtnDto> searchMachineType(SearchDtoWithoutLangCode dto) {
		PageResponseDto<MachineTypeExtnDto> pageDto = new PageResponseDto<>();
		List<MachineTypeExtnDto> machineTypes = null;

		List<SearchFilter> addList = new ArrayList<>();
		if (filterValidator.validate(MachineTypeExtnDto.class, dto.getFilters())) {
			pageUtils.validateSortField(MachineType.class, dto.getSort());
			OptionalFilter optionalFilter = new OptionalFilter(addList);
			Page<MachineType> page = masterdataSearchHelper.searchMasterdataWithoutLangCode(MachineType.class, dto,
					new OptionalFilter[] { optionalFilter });

			if (page.getContent() != null && !page.getContent().isEmpty()) {
				pageDto = PageUtils.pageResponse(page);
				machineTypes = MapperUtils.mapAll(page.getContent(), MachineTypeExtnDto.class);
				pageDto.setData(machineTypes);
			}
		}
		return pageDto;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see io.mosip.kernel.masterdata.service.MachineTypeService#
	 * machineTypesFilterValues(io.mosip.kernel.masterdata.dto.request.
	 * FilterValueDto)
	 */
	@Override
	public FilterResponseCodeDto machineTypesFilterValues(FilterValueDto filterValueDto) {
		FilterResponseCodeDto filterResponseDto = new FilterResponseCodeDto();
		List<ColumnCodeValue> columnValueList = new ArrayList<>();
		filterValueDto.setLanguageCode(null); //language agnostic entity
		if (filterColumnValidator.validate(FilterDto.class, filterValueDto.getFilters(), Machine.class)) {
			for (FilterDto filterDto : filterValueDto.getFilters()) {
				FilterResult<FilterData> filterResult = masterDataFilterHelper
						.filterValuesWithCode(MachineType.class, filterDto,
						filterValueDto,"code");
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
}
