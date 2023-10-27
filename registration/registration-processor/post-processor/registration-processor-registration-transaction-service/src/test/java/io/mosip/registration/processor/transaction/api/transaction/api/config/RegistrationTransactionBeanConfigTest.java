package io.mosip.registration.processor.transaction.api.transaction.api.config;

import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import io.mosip.registration.processor.status.validator.RegistrationStatusRequestValidator;
import io.mosip.registration.processor.status.validator.RegistrationSyncRequestValidator;

@Configuration
@EnableWebMvc
@ComponentScan(basePackages = { "io.mosip.registration.processor.transaction.api.*" })
public class RegistrationTransactionBeanConfigTest {

	@MockBean
	public RegistrationStatusRequestValidator registrationStatusRequestValidator;

	@MockBean
	public RegistrationSyncRequestValidator registrationSyncRequestValidator;
}
