package io.mosip.kernel.masterdata;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Main class of Master-Data-Service Application. This will have CRUD operations
 * related to master data
 * 
 * @author Dharmesh Khandelwal
 * @since 1.0.0
 *
 */
@SpringBootApplication(exclude = {
		org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration.class
		}, scanBasePackages = {
				"io.mosip.kernel.masterdata.*", "${mosip.auth.adapter.impl.basepackage}",
				"io.mosip.kernel.core.logger.config" })
@EnableCaching
@EnableScheduling
public class MasterDataBootApplication {

	/**
	 * Function to run the Master-Data-Service application
	 * 
	 * @param args The arguments to pass will executing the main function
	 */
	public static void main(String[] args) {
		SpringApplication.run(MasterDataBootApplication.class, args);
	}

}