package io.mosip.kernel.keymanagerservice.dto;

import java.time.LocalDateTime;

import com.fasterxml.jackson.annotation.JsonFormat;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response class for all Certificates Data.
 * 
 * @author Mahammed Taheer
 * @since 1.2.1
 *
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@ApiModel(description = "Class representing a All Certificates Data Response")
public class AllCertificatesDataResponseDto {

    /**
	 * Field for certificate
	 */
	private CertificateDataResponseDto[] allCertificates;


}
