package io.mosip.kernel.auditmanager;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Audit manager application
 * 
 * @author Dharmesh Khandelwal
 * @since 1.0.0
 *
 */
@SpringBootApplication(exclude = {
		org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration.class
		},scanBasePackages = { "io.mosip.kernel.auditmanager.*","${mosip.auth.adapter.impl.basepackage}"
		,"io.mosip.kernel.core.logger.config"})
public class AuditManagerBootApplication {

	/**
	 * Main method to run spring boot application
	 * 
	 * @param args args
	 */
	public static void main(String[] args) {
		SpringApplication.run(AuditManagerBootApplication.class, args);
	}
}
