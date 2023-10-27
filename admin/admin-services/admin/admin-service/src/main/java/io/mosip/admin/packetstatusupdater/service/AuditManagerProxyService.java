package io.mosip.admin.packetstatusupdater.service;

import io.mosip.admin.packetstatusupdater.dto.AuditManagerRequestDto;
import io.mosip.admin.packetstatusupdater.dto.AuditManagerResponseDto;

import java.util.Map;

/**
 * The Interface AuditManagerProxyService.
 * 
 * @author Megha Tanga
 */
public interface AuditManagerProxyService {

	public AuditManagerResponseDto logAdminAudit(AuditManagerRequestDto auditManagerRequestDto);

}