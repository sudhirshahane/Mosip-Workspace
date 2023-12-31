package io.mosip.kernel.masterdata.dto.getresponse;

import java.util.List;

import io.mosip.kernel.masterdata.dto.BlocklistedWordsDto;
import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * Blocklisted words response Dto
 * 
 * @author Abhishek Kumar
 * @version 1.0.0
 * @since 06-11-2018
 */
@Data
@AllArgsConstructor
public class BlocklistedWordsResponseDto {
	private List<BlocklistedWordsDto> blocklistedwords;
}
