package io.mosip.registration.controller.reg;

import java.io.Writer;
import java.net.URL;
import java.util.ResourceBundle;

import org.springframework.stereotype.Component;

import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.registration.config.AppConfig;
import io.mosip.registration.constants.RegistrationConstants;
import io.mosip.registration.context.SessionContext;
import io.mosip.registration.controller.BaseController;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.web.WebEngine;
import javafx.scene.web.WebView;

@Component
public class DashBoardController extends BaseController implements Initializable {
	
	private static final Logger LOGGER = AppConfig.getLogger(DashBoardController.class);
	
	@FXML
	private WebView dashboardWebView;
	
	private Writer stringWriter;
	
	public void setStringWriter(Writer stringWriter) {
		this.stringWriter = stringWriter;
	}

	@Override
	public void initialize(URL location, ResourceBundle resources) {
		SessionContext.map().put(RegistrationConstants.ISPAGE_NAVIGATION_ALERT_REQ,
				RegistrationConstants.ENABLE);
		
		WebEngine webEngine = dashboardWebView.getEngine();
		webEngine.loadContent(stringWriter.toString());
		
		LOGGER.info("Dashboard template has been loaded to webview");
	}

}
