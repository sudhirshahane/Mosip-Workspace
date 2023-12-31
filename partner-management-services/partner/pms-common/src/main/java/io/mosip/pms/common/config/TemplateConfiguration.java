package io.mosip.pms.common.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.mosip.kernel.core.templatemanager.spi.TemplateManager;
import io.mosip.kernel.core.templatemanager.spi.TemplateManagerBuilder;

@Configuration
public class TemplateConfiguration {

	@Bean
	public TemplateManager templateManager(TemplateManagerBuilder templateManagerBuilder) {

		return templateManagerBuilder.build();
	}
}