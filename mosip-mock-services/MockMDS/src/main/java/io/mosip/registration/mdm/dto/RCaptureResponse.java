package io.mosip.registration.mdm.dto;

import java.util.List;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RCaptureResponse {

	 public List<BioMetricsDto> biometrics;
}
