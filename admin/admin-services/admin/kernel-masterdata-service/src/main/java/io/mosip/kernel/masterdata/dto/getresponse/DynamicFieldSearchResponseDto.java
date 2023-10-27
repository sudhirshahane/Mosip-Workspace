package io.mosip.kernel.masterdata.dto.getresponse;

import java.time.LocalDateTime;

import com.fasterxml.jackson.databind.JsonNode;

import lombok.Data;

@Data
public class DynamicFieldSearchResponseDto {

    private String id;
    private String name;
    private String langCode;
    private String dataType;
    private String description;
	private JsonNode fieldVal;
    private Boolean isActive;
    private String createdBy;
    private String updatedBy;
	private LocalDateTime createdDateTime;
	private LocalDateTime updatedDateTime;

}
