package io.mosip.registration.controller.reg;

import static io.mosip.registration.constants.RegistrationConstants.APPLICATION_ID;
import static io.mosip.registration.constants.RegistrationConstants.APPLICATION_NAME;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

import io.mosip.registration.service.packet.PacketHandlerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Controller;

import io.mosip.kernel.core.exception.ExceptionUtils;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.registration.config.AppConfig;
import io.mosip.registration.constants.ProcessNames;
import io.mosip.registration.constants.RegistrationConstants;
import io.mosip.registration.constants.RegistrationUIConstants;
import io.mosip.registration.context.SessionContext;
import io.mosip.registration.controller.BaseController;
import io.mosip.registration.controller.auth.AuthenticationController;
import io.mosip.registration.exception.RegBaseCheckedException;
import io.mosip.registration.update.SoftwareUpdateHandler;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.TextArea;
import javafx.scene.image.ImageView;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.StackPane;
import javafx.scene.text.Text;
import javafx.stage.Modality;
import javafx.stage.Stage;

/**
 * {@code RegistrationController} for Registration Page Controller
 * 
 * @author Taleev.Aalam
 * @since 1.0.0
 */

@Controller
public class RegistrationController extends BaseController {

	/**
	 * Instance of {@link Logger}
	 */
	private static final Logger LOGGER = AppConfig.getLogger(RegistrationController.class);

	/*@Autowired
	private DocumentScanController documentScanController;*/
	@FXML
	private GridPane documentScan;
	@FXML
	private GridPane registrationId;
	@Autowired
	private Validations validation;
	/*@Autowired
	private MasterSyncService masterSync;*/
	@FXML
	private GridPane demographicDetail;

	@FXML
	private GridPane biometric;
	@FXML
	private GridPane operatorAuthenticationPane;
	@FXML
	public ImageView biometricTracker;
	@FXML
	private GridPane registrationPreview;

	@FXML
	private GridPane registrationHeader;

	@FXML
	private Text regTypeText;

	public Text getRegTypeText() {
		return regTypeText;
	}

	@FXML
	private Text homeText;

	@FXML
	private GridPane navigationGridPane;

	public GridPane getNavigationGridPane() {
		return navigationGridPane;
	}

	@Autowired
	private AuthenticationController authenticationController;

	@Autowired
	private SoftwareUpdateHandler softwareUpdateHandler;

	@Autowired
	private PacketHandlerService packetHandlerService;

	private List<String> selectedLangList = new LinkedList<>();

	/*public void init(String UIN, HashMap<String, Object> selectionListDTO, Map<String, UiSchemaDTO> selectedFields,
			List<String> selectedFieldGroups) {
		validation.updateAsLostUIN(false);
		createRegistrationDTOObject(RegistrationConstants.PACKET_TYPE_UPDATE);
		RegistrationDTO registrationDTO = getRegistrationDTOFromSession();
		registrationDTO.setSelectionListDTO(selectionListDTO);
		List<String> fieldIds = new ArrayList<String>(selectedFields.keySet());
		registrationDTO.setUpdatableFields(fieldIds);
		registrationDTO.addDemographicField("UIN", UIN);
		registrationDTO.setUpdatableFieldGroups(selectedFieldGroups);
		registrationDTO.setBiometricMarkedForUpdate(
				selectedFieldGroups.contains(RegistrationConstants.BIOMETRICS_GROUP) ? true : false);
	}*/

	/*protected void initializeLostUIN() {
		validation.updateAsLostUIN(true);

		createRegistrationDTOObject(RegistrationConstants.PACKET_TYPE_LOST);
	}*/

	/**
	 * This method is to go to the operator authentication page
	 */
	public void goToAuthenticationPage() {
		try {
			authenticationController.initData(ProcessNames.PACKET.getType());
		} catch (RegBaseCheckedException ioException) {
			LOGGER.error("REGISTRATION - REGSITRATION_OPERATOR_AUTHENTICATION_PAGE_LOADING_FAILED", APPLICATION_NAME,
					RegistrationConstants.APPLICATION_ID,
					ioException.getMessage() + ExceptionUtils.getStackTrace(ioException));
		}
	}

	/**
	 * This method is to determine if it is edit page
	 */
	private Boolean isEditPage() {
		if (SessionContext.map().get(RegistrationConstants.REGISTRATION_ISEDIT) != null)
			return (Boolean) SessionContext.map().get(RegistrationConstants.REGISTRATION_ISEDIT);
		return false;
	}

	/**
	 * This method will create registration DTO object
	 */
	public boolean createRegistrationDTOObject(String processId) {
		try {
			// Put the RegistrationDTO object to SessionContext Map
			SessionContext.map().put(RegistrationConstants.REGISTRATION_DATA,
					packetHandlerService.startRegistration(null, processId));
			getRegistrationDTOFromSession().setSelectedLanguagesByApplicant(selectedLangList);
			return true;
		} catch (RegBaseCheckedException ex) {
			LOGGER.error("Error when creating RegistrationDTO", ex);
		}
		return false;
	}

	/**
	 * This method will show uin update current page
	 */
	public void showUINUpdateCurrentPage() {
		LOGGER.debug(RegistrationConstants.REGISTRATION_CONTROLLER, APPLICATION_NAME,
				RegistrationConstants.APPLICATION_ID, "Setting Visibility for demo,doc,biometric,preview,auth");
		demographicDetail.setVisible(getVisiblity(RegistrationConstants.UIN_UPDATE_DEMOGRAPHICDETAIL));
		documentScan.setVisible(getVisiblity(RegistrationConstants.UIN_UPDATE_DOCUMENTSCAN));

		biometric.setVisible(getVisiblity(RegistrationConstants.UIN_UPDATE_PARENTGUARDIAN_DETAILS));
		registrationPreview.setVisible(getVisiblity(RegistrationConstants.UIN_UPDATE_REGISTRATIONPREVIEW));
		operatorAuthenticationPane
				.setVisible(getVisiblity(RegistrationConstants.UIN_UPDATE_OPERATORAUTHENTICATIONPANE));
	}

	/**
	 * This method will determine the visibility of the page
	 */
	private boolean getVisiblity(String page) {
		if (SessionContext.map().get(page) != null) {
			return (boolean) SessionContext.map().get(page);
		}
		return false;
	}

	/**
	 * This method will determine the current page
	 */
	public void showCurrentPage(String notTosShow, String show) {

		LOGGER.debug(RegistrationConstants.REGISTRATION_CONTROLLER, RegistrationConstants.APPLICATION_NAME,
				RegistrationConstants.APPLICATION_ID, "Navigating to next page based on the current page");

		getCurrentPage(registrationId, notTosShow, show);

		LOGGER.debug(RegistrationConstants.REGISTRATION_CONTROLLER, RegistrationConstants.APPLICATION_NAME,
				RegistrationConstants.APPLICATION_ID, "Navigated to next page based on the current page");
	}



	/**
	 * Display the validation failure messages
	 */
	public void displayValidationMessage(String validationMessage) {
		LOGGER.debug(RegistrationConstants.REGISTRATION_CONTROLLER, RegistrationConstants.APPLICATION_NAME,
				RegistrationConstants.APPLICATION_ID, "Showing the validation message");
		if (validationMessage.length() > 0) {
			TextArea view = new TextArea(validationMessage);
			view.setEditable(false);
			Scene scene = new Scene(new StackPane(view), 300, 200);
			Stage primaryStage = new Stage();
			primaryStage.setTitle("Invalid input");
			primaryStage.setScene(scene);
			primaryStage.sizeToScene();
			primaryStage.initModality(Modality.WINDOW_MODAL);
			primaryStage.initOwner(fXComponents.getStage());
			primaryStage.show();

			LOGGER.debug(RegistrationConstants.REGISTRATION_CONTROLLER, RegistrationConstants.APPLICATION_NAME,
					RegistrationConstants.APPLICATION_ID, "Validation message shown successfully");
		}
	}

	/**
	 * Go to home ack template.
	 */
	public void home() {
		try {
			BaseController.load(getClass().getResource(RegistrationConstants.HOME_PAGE));
			if (!(boolean) SessionContext.map().get(RegistrationConstants.ONBOARD_USER)) {
				clearOnboardData();
				clearRegistrationData();
			} else {
				SessionContext.map().put(RegistrationConstants.ISPAGE_NAVIGATION_ALERT_REQ,
						RegistrationConstants.ENABLE);
			}
		} catch (IOException ioException) {
			LOGGER.error("REGISTRATION - UI - ACK_RECEIPT_CONTROLLER", APPLICATION_NAME, APPLICATION_ID,
					ioException.getMessage() + ExceptionUtils.getStackTrace(ioException));
			generateAlert(RegistrationConstants.ERROR, RegistrationUIConstants.getMessageLanguageSpecific(RegistrationUIConstants.UNABLE_LOAD_HOME_PAGE));
		} catch (RuntimeException runtimException) {
			LOGGER.error("REGISTRATION - UI - ACK_RECEIPT_CONTROLLER", APPLICATION_NAME, APPLICATION_ID,
					runtimException.getMessage() + ExceptionUtils.getStackTrace(runtimException));
			generateAlert(RegistrationConstants.ERROR, RegistrationUIConstants.getMessageLanguageSpecific(RegistrationUIConstants.UNABLE_LOAD_HOME_PAGE));
		}

	}

	public List<String> getSelectedLangList() {
		return selectedLangList;
	}

	public void setSelectedLangList(List<String> selectedLangList) {
		this.selectedLangList = selectedLangList;
	}
}
