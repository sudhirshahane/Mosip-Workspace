package io.mosip.kernel.auditmanager.dto;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Getter;
import lombok.Setter;


@Component("authorizedRoles")
@ConfigurationProperties(prefix = "mosip.role.auditmanager")
@Getter
@Setter
public class AuthorizedRolesDTO {

	private List<String>postaudits;

}	