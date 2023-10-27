package io.mosip.kernel.lkeymanager.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import io.mosip.kernel.core.http.RequestWrapper;
import io.mosip.kernel.core.http.ResponseFilter;
import io.mosip.kernel.core.http.ResponseWrapper;
import io.mosip.kernel.core.licensekeymanager.spi.LicenseKeyManagerService;
import io.mosip.kernel.lkeymanager.dto.LicenseKeyFetchResponseDto;
import io.mosip.kernel.lkeymanager.dto.LicenseKeyGenerationDto;
import io.mosip.kernel.lkeymanager.dto.LicenseKeyGenerationResponseDto;
import io.mosip.kernel.lkeymanager.dto.LicenseKeyMappingDto;
import io.mosip.kernel.lkeymanager.dto.LicenseKeyMappingResponseDto;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * Controller class that provides various methods for license key management
 * such as to generate license key for a specified TSP ID, mapping several
 * permissions to a generated license key, fetching the specified permissions
 * for a license key.
 * 
 * @author Sagar Mahapatra
 * @since 1.0.0
 *
 */
@SuppressWarnings("java:S5122") // Need CrossOrigin access for all the APIs, added to ignore in sonarCloud Security hotspots.
@RestController
@Tag(name = "licensekey", description = "Operation related to License Key Management")
public class LicenseKeyController {
	/**
	 * Autowired reference for {@link LicenseKeyManagerService}.
	 */
	@Autowired
	LicenseKeyManagerService<String, LicenseKeyGenerationDto, LicenseKeyMappingDto> licenseKeyManagerService;

	/**
	 * This method will generate license key against a certain TSP ID.
	 * 
	 * @param licenseKeyGenerationDto the LicenseKeyGenerationResponseDto request
	 *                                object wrapped in {@link RequestWrapper}.
	 * @return the response entity.
	 */
	@Operation(summary = "This method will generate license key against a certain TSP ID", description = "Endpoint for Encrypt the data", tags = { "licensekey" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	//@PreAuthorize("hasAnyRole('ZONAL_ADMIN','GLOBAL_ADMIN','INDIVIDUAL','ID_AUTHENTICATION','TEST', 'REGISTRATION_ADMIN', 'REGISTRATION_SUPERVISOR', 'REGISTRATION_OFFICER', 'REGISTRATION_PROCESSOR','PRE_REGISTRATION_ADMIN','RESIDENT')")
	@PreAuthorize("hasAnyRole(@lkeyAuthRoles.getPostlicensegenerate())")
	@ResponseFilter
	@PostMapping(value = "/license/generate")
	public ResponseWrapper<LicenseKeyGenerationResponseDto> generateLicenseKey(
			@RequestBody RequestWrapper<LicenseKeyGenerationDto> licenseKeyGenerationDto) {
		LicenseKeyGenerationResponseDto licenseKeyGenerationResponseDto = new LicenseKeyGenerationResponseDto();
		ResponseWrapper<LicenseKeyGenerationResponseDto> responseWrapper = new ResponseWrapper<>();
		licenseKeyGenerationResponseDto
				.setLicenseKey(licenseKeyManagerService.generateLicenseKey(licenseKeyGenerationDto.getRequest()));
		responseWrapper.setResponse(licenseKeyGenerationResponseDto);
		return responseWrapper;
	}

	/**
	 * This method will map license key to several permissions. The permissions
	 * provided must be present in the master list.
	 * 
	 * @param licenseKeyMappingDto the {@link LicenseKeyMappingDto}.
	 * @return the response entity.
	 */
	@Operation(summary = "This method will map license key to several permissions. The permissions provided must be present in the master list", description = "Endpoint for Encrypt the data", tags = { "licensekey" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	@ResponseFilter
	@PostMapping(value = "/license/permission")
	public ResponseWrapper<LicenseKeyMappingResponseDto> mapLicenseKey(
			@RequestBody RequestWrapper<LicenseKeyMappingDto> licenseKeyMappingDto) {
		LicenseKeyMappingResponseDto licenseKeyMappingResponseDto = new LicenseKeyMappingResponseDto();
		ResponseWrapper<LicenseKeyMappingResponseDto> responseWrapper = new ResponseWrapper<>();
		licenseKeyMappingResponseDto
				.setStatus(licenseKeyManagerService.mapLicenseKey(licenseKeyMappingDto.getRequest()));
		responseWrapper.setResponse(licenseKeyMappingResponseDto);
		return responseWrapper;
	}

	/**
	 * This method will fetch the mapped permissions for a license key.
	 * 
	 * @param tspId      tsp id
	 * @param licenseKey the license key of which the permissions need to be
	 *                   fetched.
	 * @return the permissions fetched.
	 */
	@Operation(summary = "This method will fetch the mapped permissions for a license key", description = "Endpoint for Encrypt the data", tags = { "licensekey" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	@ResponseFilter
	@GetMapping(value = "/license/permission")
	public ResponseWrapper<LicenseKeyFetchResponseDto> fetchLicenseKeyPermissions(@RequestParam("tspId") String tspId,
			@RequestParam("licenseKey") String licenseKey) {
		LicenseKeyFetchResponseDto licenseKeyFetchResponseDto = new LicenseKeyFetchResponseDto();
		ResponseWrapper<LicenseKeyFetchResponseDto> responseWrapper = new ResponseWrapper<>();
		licenseKeyFetchResponseDto
				.setPermissions(licenseKeyManagerService.fetchLicenseKeyPermissions(tspId, licenseKey));
		responseWrapper.setResponse(licenseKeyFetchResponseDto);
		return responseWrapper;
	}
}
