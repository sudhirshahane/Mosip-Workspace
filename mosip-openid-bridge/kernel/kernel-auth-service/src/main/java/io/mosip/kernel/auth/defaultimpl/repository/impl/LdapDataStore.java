/**
 * 
 */
package io.mosip.kernel.auth.defaultimpl.repository.impl;

import java.io.IOException;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import javax.naming.Context;
import javax.naming.NameAlreadyBoundException;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

import org.apache.directory.api.ldap.model.constants.LdapSecurityConstants;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.password.PasswordDetails;
import org.apache.directory.api.ldap.model.password.PasswordUtil;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.assertj.core.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.mosip.kernel.auth.defaultimpl.config.MosipEnvironment;
import io.mosip.kernel.auth.defaultimpl.constant.AuthConstant;
import io.mosip.kernel.auth.defaultimpl.constant.AuthErrorCode;
import io.mosip.kernel.auth.defaultimpl.constant.LDAPErrorCode;
import io.mosip.kernel.auth.defaultimpl.constant.LdapConstants;
import io.mosip.kernel.auth.defaultimpl.dto.DataBaseProps;
import io.mosip.kernel.auth.defaultimpl.dto.LdapControl;
import io.mosip.kernel.auth.defaultimpl.exception.AuthManagerException;
import io.mosip.kernel.auth.defaultimpl.repository.DataStore;
import io.mosip.kernel.auth.defaultimpl.util.TokenGenerator;
import io.mosip.kernel.auth.defaultimpl.util.TokenValidator;
import io.mosip.kernel.core.authmanager.model.AuthZResponseDto;
import io.mosip.kernel.core.authmanager.model.ClientSecret;
import io.mosip.kernel.core.authmanager.model.LoginUser;
import io.mosip.kernel.core.authmanager.model.MosipUserDto;
import io.mosip.kernel.core.authmanager.model.MosipUserListDto;
import io.mosip.kernel.core.authmanager.model.MosipUserSalt;
import io.mosip.kernel.core.authmanager.model.MosipUserSaltListDto;
import io.mosip.kernel.core.authmanager.model.OtpUser;
import io.mosip.kernel.core.authmanager.model.PasswordDto;
import io.mosip.kernel.core.authmanager.model.RIdDto;
import io.mosip.kernel.core.authmanager.model.Role;
import io.mosip.kernel.core.authmanager.model.RolesListDto;
import io.mosip.kernel.core.authmanager.model.UserDetailsDto;
import io.mosip.kernel.core.authmanager.model.UserDetailsResponseDto;
import io.mosip.kernel.core.authmanager.model.UserNameDto;
import io.mosip.kernel.core.authmanager.model.UserOtp;
import io.mosip.kernel.core.authmanager.model.UserPasswordRequestDto;
import io.mosip.kernel.core.authmanager.model.UserPasswordResponseDto;
import io.mosip.kernel.core.authmanager.model.UserRegistrationRequestDto;
import io.mosip.kernel.core.authmanager.model.ValidationResponseDto;
import io.mosip.kernel.core.authmanager.model.IndividualIdDto;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.core.util.HMACUtils;

/**
 * @author Ramadurai Pandian
 *
 */

@Component
@Deprecated
public class LdapDataStore implements DataStore {

	private static final Logger LOGGER = LoggerFactory.getLogger(LdapDataStore.class);
	private DataBaseProps dataBaseConfig;

	public LdapDataStore() {
	}

	public LdapDataStore(DataBaseProps dataBaseConfig) {
		super();
		this.dataBaseConfig = dataBaseConfig;
	}

	@Autowired
	TokenGenerator tokenGenerator;

	@Autowired
	TokenValidator tokenValidator;

	@Autowired
	MosipEnvironment environment;

	@Value("${mosip.kernel.ldap-provider-url:ldap://localhost:389}")
	private String ldapProviderURL;

	@Value("${mosip.kernel.ldap-security-principal:uid=admin,ou=system}")
	private String ldapSecurityPrincipal;

	@Value("${mosip.kernel.ldap-security-credentials:#{null}}")
	private String ldapSecurityCredentials;

	public LdapConnection createAnonymousConnection() throws Exception {
		LdapConnection connection = new LdapNetworkConnection(dataBaseConfig.getUrl(),
				Integer.valueOf(dataBaseConfig.getPort()));
		return connection;
	}

	public LdapContext getContext() throws NamingException {

		Hashtable<String, String> env = new Hashtable<String, String>();
		if (!env.containsKey(Context.INITIAL_CONTEXT_FACTORY))
			env.put(Context.INITIAL_CONTEXT_FACTORY, LdapConstants.LDAP_INITAL_CONTEXT_FACTORY);
		// env.put(Context.PROVIDER_URL, "ldap://52.172.11.190:10389");
		if (Strings.isNullOrEmpty(ldapProviderURL) || Strings.isNullOrEmpty(ldapSecurityCredentials)) {
			LOGGER.error("Ldap url or credential properties empty or null ");
			throw new NamingException("Ldap url or credential properties empty or null");
		}
		env.put(Context.PROVIDER_URL, ldapProviderURL);
		// env.put(Context.SECURITY_PRINCIPAL, "uid=admin,ou=system");
		env.put(Context.SECURITY_PRINCIPAL, ldapSecurityPrincipal);
		// env.put(Context.SECURITY_CREDENTIALS, "secret");
		env.put(Context.SECURITY_CREDENTIALS, ldapSecurityCredentials);
		LdapContext context = new InitialLdapContext(env, null);
		LdapControl ldapControl = new LdapControl();
		context.setRequestControls(ldapControl.getControls());
		return context;
	}

	@Override
	public MosipUserDto authenticateUser(LoginUser loginUser) throws Exception {
		MosipUserDto mosipUser = getLoginDetails(loginUser);
		return mosipUser;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * io.mosip.kernel.auth.service.AuthNService#authenticateWithOtp(io.mosip.kernel
	 * .auth.entities.otp.OtpUser)
	 */
	@Override
	public MosipUserDto authenticateWithOtp(OtpUser otpUser) throws Exception {
		MosipUserDto mosipUser = getOtpDetails(otpUser);
		return mosipUser;
	}

	private MosipUserDto getOtpDetails(OtpUser otpUser) throws Exception {
		LdapConnection connection = createAnonymousConnection();
		MosipUserDto mosipUserDto = null;
		Dn userdn = null;
		try {
			userdn = createUserDn(otpUser.getUserId());
			mosipUserDto = lookupUserDetails(userdn, connection);
			if (!connection.exists(userdn)) {
				throw new AuthManagerException(AuthErrorCode.USER_VALIDATION_ERROR.getErrorCode(),
						AuthErrorCode.USER_VALIDATION_ERROR.getErrorMessage());

			}
		} catch (Exception e) {
			throw new AuthManagerException(LDAPErrorCode.LDAP_CONNECTION_ERROR.getErrorCode(),
					LDAPErrorCode.LDAP_CONNECTION_ERROR.getErrorMessage(), e);
		} finally {
			connection.close();
		}
		return mosipUserDto;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * io.mosip.kernel.auth.service.AuthNService#authenticateUserWithOtp(io.mosip.
	 * kernel.auth.entities.UserOtp)
	 */
	@Override
	public MosipUserDto authenticateUserWithOtp(UserOtp userOtp) throws Exception {
		MosipUserDto mosipUserDto = getMosipUser(userOtp.getUserId());
		return mosipUserDto;
	}

	private MosipUserDto getMosipUser(String userId) throws Exception {
		LdapConnection connection = null;
		MosipUserDto mosipUserDto = null;
		try {
			connection = createAnonymousConnection();
			Dn userdn = createUserDn(userId);
			mosipUserDto = lookupUserDetails(userdn, connection);
		} catch (Exception e) {
			throw new AuthManagerException(LDAPErrorCode.LDAP_CONNECTION_ERROR.getErrorCode(),
					LDAPErrorCode.LDAP_CONNECTION_ERROR.getErrorMessage(), e);
		} finally {
			if (connection != null)
				connection.close();
		}
		return mosipUserDto;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * io.mosip.kernel.auth.service.AuthNService#authenticateWithSecretKey(io.mosip.
	 * kernel.auth.entities.ClientSecret)
	 */
	@Override
	public MosipUserDto authenticateWithSecretKey(ClientSecret clientSecret) throws Exception {
		MosipUserDto mosipUser = getClientSecretDetails(clientSecret);
		return mosipUser;
	}

	private MosipUserDto getClientSecretDetails(ClientSecret clientSecret) throws Exception {
		LdapConnection connection = null;
		try {
			connection = createAnonymousConnection();
			Dn userdn = createUserDn(clientSecret.getClientId());
			connection.bind(userdn, clientSecret.getSecretKey());
			if (connection.isAuthenticated()) {
				return lookupUserDetails(userdn, connection);
			}
		} catch (Exception ex) {
			throw new AuthManagerException(LDAPErrorCode.LDAP_CONNECTION_ERROR.getErrorCode(),
					LDAPErrorCode.LDAP_CONNECTION_ERROR.getErrorMessage(), ex);
		} finally {
			if (connection != null) {
				connection.unBind();
				connection.close();
			}
		}
		return null;
	}
	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * io.mosip.kernel.auth.service.AuthZService#verifyOtp(io.mosip.kernel.auth.
	 * entities.otp.OtpValidateRequestDto, java.lang.String)
	 */

	public MosipUserDto getLoginDetails(LoginUser loginUser) throws Exception {
		LdapConnection connection = null;
		try {
			connection = createAnonymousConnection();
			Dn userdn = createUserDn(loginUser.getUserName());
			connection.bind(userdn, loginUser.getPassword());
			if (connection.isAuthenticated()) {
				return lookupUserDetails(userdn, connection);
			}
		} catch (Exception ex) {
			throw new AuthManagerException(LDAPErrorCode.LDAP_CONNECTION_ERROR.getErrorCode(),
					LDAPErrorCode.LDAP_CONNECTION_ERROR.getErrorMessage(), ex);
		} finally {
			if (connection != null) {
				connection.unBind();
				connection.close();
			}
		}
		return null;
	}

	private MosipUserDto lookupUserDetails(Dn userdn, LdapConnection connection) throws Exception {
		try {
			// if lookup access is retricted only to admin then bind the
			// connection with
			// admin details
			// connection.bind(createAdminDn(),
			// mosipEnvironment.getLdapAdminPassword());

			Collection<String> roles = getUserRoles(userdn, connection);
			String rolesString = convertRolesToString(roles);
			MosipUserDto mosipUserDto = null;

			Entry userLookup = connection.lookup(userdn);
			if (userLookup != null) {
				mosipUserDto = new MosipUserDto();
				mosipUserDto.setUserId(userLookup.get("uid").get().toString());
				mosipUserDto
						.setMobile(userLookup.get("mobile") != null ? userLookup.get("mobile").get().toString() : null);
				mosipUserDto.setMail(userLookup.get("mail") != null ? userLookup.get("mail").get().toString() : null);
				if (userLookup.get("userPassword") != null) {
					PasswordDetails password = PasswordUtil
							.splitCredentials(userLookup.get("userPassword").get().getBytes());
					mosipUserDto.setUserPassword(
							userLookup.get("userPassword") != null ? HMACUtils.digestAsPlainText(password.getPassword())
									: null);
				}
				// mosipUserDto.setLangCode(userLookup.get("preferredLanguage").get().toString());
				mosipUserDto.setName(userLookup.get("cn").get().toString());
				if (userLookup.get("rid") != null) {
					mosipUserDto.setRId(userLookup.get("rid").get().toString());
				}
				mosipUserDto.setRole(rolesString);
			}
			return mosipUserDto;
		} catch (Exception ex) {
			throw new AuthManagerException(LDAPErrorCode.LDAP_PARSE_REQUEST_ERROR.getErrorCode(),
					LDAPErrorCode.LDAP_PARSE_REQUEST_ERROR.getErrorMessage(), ex);
		}
	}

	private Collection<String> getUserRoles(Dn userdn, LdapConnection connection) {
		try {
			Dn searchBase = new Dn("ou=roles,c=mycountry");
			String searchFilter = "(&(objectClass=organizationalRole)(roleOccupant=" + userdn + "))";

			EntryCursor rolesData = connection.search(searchBase, searchFilter, SearchScope.ONELEVEL);

			Set<String> roles = new HashSet<String>();
			for (Entry entry : rolesData) {
				roles.add(entry.get("cn").getString());
			}

			rolesData.close();
			return roles;
		} catch (Exception ex) {
			throw new AuthManagerException(LDAPErrorCode.LDAP_ROLES_REQUEST_ERROR.getErrorCode(),
					LDAPErrorCode.LDAP_ROLES_REQUEST_ERROR.getErrorMessage(), ex);
		}
	}

	private String convertRolesToString(Collection<String> roles) throws Exception {
		StringBuilder rolesString = new StringBuilder();
		for (String role : roles) {
			rolesString.append(role);
			rolesString.append(",");
		}

		return rolesString.length() > 0 ? rolesString.substring(0, rolesString.length() - 1) : "";
	}

	private Dn createUserDn(String userName) throws LdapInvalidDnException {
		userName = escapeLDAPValue(userName);
		return new Dn("uid=" + userName + ",ou=people,c=mycountry");
	}

	private Dn createRoleDn(String role) throws LdapInvalidDnException {
		role = escapeLDAPValue(role);
		return new Dn("cn=" + role + ",ou=roles,c=mycountry");
	}

	@Override
	public RolesListDto getAllRoles(String appId) {
		RolesListDto rolesListDto = new RolesListDto();
		EntryCursor rolesData = null;
		LdapConnection connection = null;
		try {
			connection = createAnonymousConnection();
			List<Role> roleDtos = new ArrayList<>();
			Dn searchBase = new Dn("ou=roles,c=mycountry");
			String searchFilter = "(objectClass=organizationalRole)";

			rolesData = connection.search(searchBase, searchFilter, SearchScope.ONELEVEL);

			for (Entry entry : rolesData) {
				Role roleDto = new Role();
				roleDto.setRoleId(entry.get("cn").get().toString());
				roleDto.setRoleName(entry.get("cn").get().toString());
				roleDto.setRoleDescription(entry.get("description").get().toString());
				roleDtos.add(roleDto);
			}
			rolesListDto.setRoles(roleDtos);

			return rolesListDto;
		} catch (Exception e) {
			throw new AuthManagerException(LDAPErrorCode.LDAP_ROLES_REQUEST_ERROR.getErrorCode(),
					LDAPErrorCode.LDAP_ROLES_REQUEST_ERROR.getErrorMessage(), e);
		} finally {
			try {
				if (rolesData != null)
					rolesData.close();
				if (connection != null)
					connection.close();
			} catch (IOException e) {
				LOGGER.error(e.getMessage());
			}
		}
	}

	@Override
	public MosipUserListDto getListOfUsersDetails(List<String> users, String appId) throws Exception {
		LdapConnection connection = null;
		try {
			MosipUserListDto userResponseDto = new MosipUserListDto();
			List<MosipUserDto> mosipUserDtos = new ArrayList<>();

			connection = createAnonymousConnection();

			for (String user : users) {
				Dn userdn = createUserDn(user);
				MosipUserDto data = lookupUserDetails(userdn, connection);
				if (data != null)
					mosipUserDtos.add(data);
			}

			userResponseDto.setMosipUserDtoList(mosipUserDtos);
			return userResponseDto;
		} catch (Exception ex) {
			throw new AuthManagerException(LDAPErrorCode.LDAP_ROLES_REQUEST_ERROR.getErrorCode(),
					LDAPErrorCode.LDAP_ROLES_REQUEST_ERROR.getErrorMessage(), ex);
		} finally {
			if (connection != null)
				connection.close();
		}
	}

	@Override
	public MosipUserSaltListDto getAllUserDetailsWithSalt(List<String> userDetails, String appId) throws Exception {
		MosipUserSaltListDto mosipUserSaltList = new MosipUserSaltListDto();
		List<MosipUserSalt> mosipUserDtos = new ArrayList<>();
		LdapConnection connection = null;
		try {
			connection = createAnonymousConnection();
			Dn searchBase = new Dn("ou=people,c=mycountry");
			String searchFilter = "(&(objectClass=organizationalPerson)(objectClass=inetOrgPerson))";
			EntryCursor peoplesData = connection.search(searchBase, searchFilter, SearchScope.ONELEVEL);
			for (Entry entry : peoplesData) {
				MosipUserSalt saltDetails = new MosipUserSalt();
				saltDetails.setUserId(entry.get("uid").get().toString());
				if (entry.get("userPassword") != null) {
					PasswordDetails password = PasswordUtil
							.splitCredentials(entry.get("userPassword").get().getBytes());
					if (password.getSalt() != null) {
						saltDetails.setSalt(CryptoUtil.encodeBase64(password.getSalt()));
					}
				}
				mosipUserDtos.add(saltDetails);
			}
		} catch (Exception e) {
			throw new AuthManagerException(LDAPErrorCode.LDAP_CONNECTION_ERROR.getErrorCode(),
					LDAPErrorCode.LDAP_CONNECTION_ERROR.getErrorMessage(), e);
		} finally {
			if (connection != null)
				connection.close();
		}
		mosipUserSaltList.setMosipUserSaltList(mosipUserDtos);
		return mosipUserSaltList;
	}

	@Override
	public RIdDto getRidFromUserId(String userId, String appId) throws Exception {
		RIdDto ridDto = null;
		LdapConnection ldapConnection = null;
		try {
			ldapConnection = createAnonymousConnection();
			Dn userdn = createUserDn(userId);
			MosipUserDto data = lookupUserDetails(userdn, ldapConnection);
			if (data == null) {
				throw new AuthManagerException(AuthErrorCode.USER_VALIDATION_ERROR.getErrorCode(),
						AuthErrorCode.USER_VALIDATION_ERROR.getErrorMessage());
			}
			if (data.getRId() != null) {
				ridDto = new RIdDto();
				ridDto.setRId(data.getRId());
			}
		} finally {
			if (ldapConnection != null)
				ldapConnection.close();
		}
		return ridDto;
	}

	@Override
	public AuthZResponseDto unBlockAccount(String userId) throws Exception {

		LdapContext context = null;
		AuthZResponseDto authZResponseDto = null;
		try {
			context = getContext();
			ModificationItem[] modItems = new ModificationItem[2];
			modItems[0] = new ModificationItem(DirContext.REMOVE_ATTRIBUTE,
					new BasicAttribute(LdapConstants.PWD_ACCOUNT_LOCKED_TIME_ATTRIBUTE));
			modItems[1] = new ModificationItem(DirContext.REMOVE_ATTRIBUTE,
					new BasicAttribute(LdapConstants.PWD_FAILURE_TIME_ATTRIBUTE));
			userId = escapeLDAPValue(userId);
			context.modifyAttributes("uid=" + userId + ",ou=people,c=mycountry", modItems);
			authZResponseDto = new AuthZResponseDto();
			authZResponseDto.setMessage("Successfully Unblocked");
			authZResponseDto.setStatus("Success");
			closeContext(context);
		} catch (NamingException e) {
			closeContext(context);
			throw new AuthManagerException(AuthErrorCode.NAMING_EXCEPTION.getErrorCode(),
					AuthErrorCode.NAMING_EXCEPTION.getErrorMessage() + "" + e.getExplanation());
		}
		return authZResponseDto;
	}

	@Override
	public AuthZResponseDto changePassword(PasswordDto passwordDto) {
		LdapContext ldapContext = null;
		AuthZResponseDto authZResponseDto = null;
		String mailId = null;
		String userId = null;
		try {
			ldapContext = getContext();
		} catch (NamingException e) {
			throw new AuthManagerException(AuthErrorCode.NAMING_EXCEPTION.getErrorCode(),
					AuthErrorCode.NAMING_EXCEPTION.getErrorMessage());
		}
		try {

			NamingEnumeration<SearchResult> userDetailSearchResult = getUserDetailSearchResult(passwordDto.getUserId());
			while (userDetailSearchResult.hasMore()) {
				SearchResult searchObject = userDetailSearchResult.next();
				mailId = (String) searchObject.getAttributes().get(LdapConstants.MAIL).get();
				userId = (String) searchObject.getAttributes().get("uid").get();
			}
			String ldapPassword = getPassword(passwordDto.getUserId(), ldapContext);
			Objects.requireNonNull(ldapPassword);
			boolean isNotMatching = isNotAMatchWithUserOrEmail(userId, mailId, passwordDto.getNewPassword());

			validateOldPassword(passwordDto.getOldPassword(), ldapPassword);

			if (!isNotMatching && !passwordDto.getOldPassword().equals(passwordDto.getNewPassword())) {
				byte[] newUserPassword = PasswordUtil.createStoragePassword(passwordDto.getNewPassword().getBytes(),
						LdapSecurityConstants.getAlgorithm(passwordDto.getHashAlgo()));

				ModificationItem[] modItems = new ModificationItem[1];
				modItems[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE,
						new BasicAttribute("userPassword", newUserPassword));
				String uid = escapeLDAPValue(passwordDto.getUserId());
				ldapContext.modifyAttributes("uid=" + uid + ",ou=people,c=mycountry", modItems);
				authZResponseDto = new AuthZResponseDto();
				authZResponseDto.setMessage("Successfully changed");
				authZResponseDto.setStatus("Success");
			} else {
				throw new AuthManagerException(AuthErrorCode.PASSWORD_POLICY_EXCEPTION.getErrorCode(),
						AuthErrorCode.PASSWORD_POLICY_EXCEPTION.getErrorMessage());
			}
			closeContext(ldapContext);
		} catch (Exception e) {
			closeContext(ldapContext);
			throw new AuthManagerException(AuthErrorCode.SERVER_ERROR.getErrorCode(),
					AuthErrorCode.SERVER_ERROR.getErrorMessage() + " " + e.getCause());
		}
		return authZResponseDto;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * io.mosip.kernel.auth.factory.IDataStore#resetPassword(io.mosip.kernel.auth.
	 * entities.PasswordDto)
	 */
	@Override
	public AuthZResponseDto resetPassword(PasswordDto passwordDto) {
		LdapContext ldapContext = null;
		AuthZResponseDto authZResponseDto = null;
		String mailId = null;
		String userId = null;
		try {
			ldapContext = getContext();
			NamingEnumeration<SearchResult> userDetailSearchResult = getUserDetailSearchResult(passwordDto.getUserId());
			while (userDetailSearchResult.hasMore()) {
				SearchResult searchObject = userDetailSearchResult.next();
				mailId = (String) searchObject.getAttributes().get(LdapConstants.MAIL).get();
				userId = (String) searchObject.getAttributes().get("uid").get();
			}
			boolean isNotMatching = isNotAMatchWithUserOrEmail(userId, mailId, passwordDto.getNewPassword());
			if (!isNotMatching) {
				byte[] newUserPassword = PasswordUtil.createStoragePassword(passwordDto.getNewPassword().getBytes(),
						LdapSecurityConstants.getAlgorithm(passwordDto.getHashAlgo()));

				ModificationItem[] modItems = new ModificationItem[1];
				modItems[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE,
						new BasicAttribute("userPassword", newUserPassword));
				String uid = escapeLDAPValue(passwordDto.getUserId());
				ldapContext.modifyAttributes("uid=" + uid + ",ou=people,c=mycountry", modItems);

				authZResponseDto = new AuthZResponseDto();
				authZResponseDto.setMessage("Successfully the password has been reset");
				authZResponseDto.setStatus("Success");
			} else {
				throw new AuthManagerException(AuthErrorCode.PASSWORD_POLICY_EXCEPTION.getErrorCode(),
						AuthErrorCode.PASSWORD_POLICY_EXCEPTION.getErrorMessage());
			}
			closeContext(ldapContext);
		} catch (LdapInvalidDnException ex) {
			closeContext(ldapContext);
			throw new AuthManagerException(AuthErrorCode.INVALID_DN.getErrorCode(),
					AuthErrorCode.INVALID_DN.getErrorMessage() + ex.getCause());
		} catch (NamingException ex) {
			closeContext(ldapContext);
			throw new AuthManagerException(AuthErrorCode.NAMING_EXCEPTION.getErrorCode(),
					AuthErrorCode.NAMING_EXCEPTION.getErrorMessage() + ex.getCause());
		}
		return authZResponseDto;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * io.mosip.kernel.auth.factory.IDataStore#getUserNameBasedOnMobileNumber(java.
	 * lang.String)
	 */
	@Override
	public UserNameDto getUserNameBasedOnMobileNumber(String mobileNumber) throws Exception {
		NamingEnumeration<SearchResult> searchResult = getUserDetail(mobileNumber);
		UserNameDto userNameDto = new UserNameDto();
		if (!searchResult.hasMore()) {
			throw new AuthManagerException(AuthErrorCode.MOBILE_NOT_REGISTERED.getErrorCode(),
					AuthErrorCode.MOBILE_NOT_REGISTERED.getErrorMessage());
		}
		while (searchResult.hasMore()) {
			Attributes attributes = searchResult.next().getAttributes();
			Attribute uid = attributes.get("uid");
			userNameDto.setUserName((String) uid.get());
		}

		return userNameDto;
	}

	/**
	 * @param userid
	 * @param ldapContext
	 * @return
	 * @throws Exception
	 */
	private String getPassword(String userid, LdapContext ldapContext) throws Exception {
		String encryptedPassword = null;
		userid = escapeLDAPValue(userid);
		Dn searchBase = new Dn("uid=" + userid + ",ou=people,c=mycountry");
		SearchControls searchControls = new SearchControls();
		searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		NamingEnumeration<SearchResult> searchResult = ldapContext.search(searchBase.getName(),
				"(&(objectClass=organizationalPerson)(objectClass=inetOrgPerson)(objectClass=person))", searchControls);
		while (searchResult.hasMore()) {
			SearchResult result = searchResult.next();
			byte[] encryptedPasswordBytes = (byte[]) result.getAttributes().get("userPassword").get();
			encryptedPassword = new String(encryptedPasswordBytes);

		}
		return encryptedPassword;
	}

	/**
	 * TBD
	 * 
	 * @param oldPassword
	 * @param hashedPassword
	 * @param userId
	 * @return
	 * @throws Exception
	 */
	private void validateOldPassword(String oldPassword, String hashedPassword) {

		boolean password = PasswordUtil.compareCredentials(oldPassword.getBytes(), hashedPassword.getBytes());
		if (!password) {
			throw new AuthManagerException(AuthErrorCode.OLD_PASSWORD_NOT_MATCH.getErrorCode(),
					AuthErrorCode.OLD_PASSWORD_NOT_MATCH.getErrorMessage());
		}
	}

	/**
	 * Check password matches with either userid or email id. At most 3 letters can
	 * match with the password.
	 * 
	 * @param userId   - user id
	 * @param email    - email
	 * @param password - password
	 * @return {@link boolean}
	 */
	private boolean isNotAMatchWithUserOrEmail(String userId, String email, String password) {

		return (password.contains(userId) || password.contains(email));
	}

	@Override
	public MosipUserDto registerUser(UserRegistrationRequestDto userCreationRequestDto) {
		Dn userDn = null;
		DirContext context = null;
		try {
			context = getDirContext();
			userDn = createUserDn(userCreationRequestDto.getUserName());
			List<Attribute> attributes = new ArrayList<>();
			attributes.add(new BasicAttribute(LdapConstants.CN, escapeLDAPValue(userCreationRequestDto.getUserName())));
			attributes.add(new BasicAttribute(LdapConstants.SN, escapeLDAPValue(userCreationRequestDto.getUserName())));
			attributes
					.add(new BasicAttribute(LdapConstants.MAIL, escapeLDAPValue(userCreationRequestDto.getEmailID())));
			attributes.add(
					new BasicAttribute(LdapConstants.MOBILE, escapeLDAPValue(userCreationRequestDto.getContactNo())));
			attributes.add(new BasicAttribute(LdapConstants.DOB,
					escapeLDAPValue(userCreationRequestDto.getDateOfBirth().toString())));
			attributes.add(new BasicAttribute(LdapConstants.FIRST_NAME,
					escapeLDAPValue(userCreationRequestDto.getFirstName())));
			attributes.add(
					new BasicAttribute(LdapConstants.LAST_NAME, escapeLDAPValue(userCreationRequestDto.getLastName())));
			attributes.add(
					new BasicAttribute(LdapConstants.GENDER_CODE, escapeLDAPValue(userCreationRequestDto.getGender())));
			attributes.add(new BasicAttribute(LdapConstants.IS_ACTIVE, LdapConstants.FALSE));
			Attribute oc = new BasicAttribute(LdapConstants.OBJECT_CLASS);
			oc.add(LdapConstants.INET_ORG_PERSON);
			oc.add(LdapConstants.ORGANIZATIONAL_PERSON);
			oc.add(LdapConstants.PERSON);
			oc.add(LdapConstants.TOP);
			oc.add(LdapConstants.USER_DETAILS);
			attributes.add(oc);

			BasicAttributes entry = new BasicAttributes();
			attributes.parallelStream().forEach(entry::put);
			context.createSubcontext(userDn.getName(), entry);

		} catch (NameAlreadyBoundException exception) {
			throw new AuthManagerException(AuthErrorCode.USER_ALREADY_EXIST.getErrorCode(),
					AuthErrorCode.USER_ALREADY_EXIST.getErrorMessage());
		} catch (NameNotFoundException exception) {
			rollbackUser(userDn, context);
			throw new AuthManagerException(AuthErrorCode.ROLE_NOT_FOUND.getErrorCode(),
					AuthErrorCode.ROLE_NOT_FOUND.getErrorMessage() + exception.getMessage());
		} catch (NamingException exception) {
			throw new AuthManagerException(AuthErrorCode.USER_CREATE_EXCEPTION.getErrorCode(),
					AuthErrorCode.USER_CREATE_EXCEPTION.getErrorMessage() + exception.getMessage());
		} catch (LdapInvalidDnException exception) {
			throw new AuthManagerException(AuthErrorCode.INVALID_DN.getErrorCode(),
					AuthErrorCode.INVALID_DN.getErrorMessage() + exception.getMessage());
		}
		try {
			Dn roleOccupant = createRoleDn(userCreationRequestDto.getRole());
			ModificationItem[] mods = new ModificationItem[1];
			mods[0] = new ModificationItem(DirContext.ADD_ATTRIBUTE,
					new BasicAttribute(LdapConstants.ROLE_OCCUPANT, userDn.getName()));
			context.modifyAttributes(roleOccupant.getName(), mods);
		} catch (NameAlreadyBoundException exception) {
			rollbackUser(userDn, context);
			throw new AuthManagerException(AuthErrorCode.USER_ALREADY_EXIST.getErrorCode(),
					AuthErrorCode.USER_ALREADY_EXIST.getErrorMessage());
		} catch (NameNotFoundException exception) {
			rollbackUser(userDn, context);
			throw new AuthManagerException(AuthErrorCode.ROLE_NOT_FOUND.getErrorCode(),
					AuthErrorCode.ROLE_NOT_FOUND.getErrorMessage() + exception.getMessage());
		} catch (NamingException exception) {
			rollbackUser(userDn, context);
			throw new AuthManagerException(AuthErrorCode.USER_CREATE_EXCEPTION.getErrorCode(),
					AuthErrorCode.USER_CREATE_EXCEPTION.getErrorMessage() + exception.getMessage());
		} catch (LdapInvalidDnException exception) {
			rollbackUser(userDn, context);
			throw new AuthManagerException(AuthErrorCode.INVALID_DN.getErrorCode(),
					AuthErrorCode.INVALID_DN.getErrorMessage() + exception.getMessage());
		}
		MosipUserDto dto = new MosipUserDto();
		dto.setUserId(userCreationRequestDto.getUserName());
		return dto;

	}

	public DirContext getDirContext() throws NamingException {
		Hashtable<String, String> env = new Hashtable<>();
		env.put(Context.INITIAL_CONTEXT_FACTORY, AuthConstant.LDAP_INITAL_CONTEXT_FACTORY);
		env.put(Context.PROVIDER_URL, ldapProviderURL);
		env.put(Context.SECURITY_PRINCIPAL, ldapSecurityPrincipal);
		env.put(Context.SECURITY_CREDENTIALS, ldapSecurityCredentials);
		return new InitialDirContext(env);
	}

	@Override
	public UserPasswordResponseDto addPassword(UserPasswordRequestDto userPasswordRequestDto) {
		Dn userDn = null;
		DirContext context = null;
		Hashtable<String, String> env = new Hashtable<>();
		env.put(Context.INITIAL_CONTEXT_FACTORY, AuthConstant.LDAP_INITAL_CONTEXT_FACTORY);
		env.put(Context.PROVIDER_URL, ldapProviderURL);
		env.put(Context.SECURITY_PRINCIPAL, ldapSecurityPrincipal);
		env.put(Context.SECURITY_CREDENTIALS, ldapSecurityCredentials);
		try {
			userDn = createUserDn(userPasswordRequestDto.getUserName());
			context = new InitialDirContext(env);
			ModificationItem[] mods = new ModificationItem[3];
			mods[0] = new ModificationItem(DirContext.ADD_ATTRIBUTE,
					new BasicAttribute(LdapConstants.RID, userPasswordRequestDto.getRid()));
			mods[1] = new ModificationItem(DirContext.ADD_ATTRIBUTE,
					new BasicAttribute(LdapConstants.USER_PASSWORD, userPasswordRequestDto.getPassword()));
			mods[2] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE,
					new BasicAttribute(LdapConstants.IS_ACTIVE, LdapConstants.TRUE));
			context.modifyAttributes(userDn.getName(), mods);

		} catch (NamingException exception) {
			throw new AuthManagerException(AuthErrorCode.USER_PASSWORD_EXCEPTION.getErrorCode(),
					AuthErrorCode.USER_PASSWORD_EXCEPTION.getErrorMessage() + exception.getMessage());
		} catch (LdapInvalidDnException exception) {
			throw new AuthManagerException(AuthErrorCode.INVALID_DN.getErrorCode(),
					AuthErrorCode.INVALID_DN.getErrorMessage() + exception.getMessage());
		}
		return new UserPasswordResponseDto(userPasswordRequestDto.getUserName());
	}

	private void rollbackUser(Dn userDn, DirContext context) {
		try {
			if (context != null && userDn != null)
				context.destroySubcontext(userDn.getName());
		} catch (NamingException exception) {
			throw new AuthManagerException(AuthErrorCode.ROLLBACK_USER_EXCEPTION.getErrorCode(),
					AuthErrorCode.ROLLBACK_USER_EXCEPTION.getErrorMessage());
		}
	}

	@Override
	public MosipUserDto getUserRoleByUserId(String username) throws Exception {
		LdapConnection ldapConnection = null;
		MosipUserDto data = null;
		try {
			ldapConnection = createAnonymousConnection();
			Dn userdn = createUserDn(username);
			data = lookupUserDetails(userdn, ldapConnection);
			if (data == null) {
				throw new AuthManagerException(AuthErrorCode.USER_VALIDATION_ERROR.getErrorCode(),
						AuthErrorCode.USER_VALIDATION_ERROR.getErrorMessage());
			}
		} catch (Exception e) {
			throw new AuthManagerException(LDAPErrorCode.LDAP_CONNECTION_ERROR.getErrorCode(),
					LDAPErrorCode.LDAP_CONNECTION_ERROR.getErrorMessage(), e);
		} finally {
			if (ldapConnection != null)
				ldapConnection.close();
		}
		return data;
	}

	@Override
	public MosipUserDto getUserDetailBasedonMobileNumber(String mobileNumber) throws Exception {
		MosipUserDto mosipUserDto = new MosipUserDto();
		try {
			if (!IsValidPhoneNumber(mobileNumber)) {
				throw new LdapInvalidDnException("Invalid phone number");
			}

			LdapContext context = getContext();
			NamingEnumeration<SearchResult> searchResult = getUserDetail(mobileNumber);

			while (searchResult.hasMore()) {
				Attributes attributes = searchResult.next().getAttributes();
				mosipUserDto.setUserId((String) attributes.get("uid").get());
				String rolesAsString = getRolesBasedOnUid((String) attributes.get("uid").get());
				mosipUserDto.setMail((String) attributes.get("mail").get());
				mosipUserDto.setMobile((String) attributes.get("mobile").get());
				mosipUserDto.setName((String) attributes.get("cn").get());
				mosipUserDto.setRole(rolesAsString);
				context.close();
			}
		} catch (NamingException e) {
			throw new AuthManagerException(AuthErrorCode.NAMING_EXCEPTION.getErrorCode(),
					AuthErrorCode.NAMING_EXCEPTION.getErrorMessage());
		} catch (LdapInvalidDnException e) {
			throw new AuthManagerException(AuthErrorCode.NAMING_EXCEPTION.getErrorCode(),
					AuthErrorCode.NAMING_EXCEPTION.getErrorMessage() + " " + e.getCause());
		}

		return mosipUserDto;
	}

	private NamingEnumeration<SearchResult> getUserDetail(String mobileNumber)
			throws LdapInvalidDnException, NamingException {

		if (!IsValidPhoneNumber(mobileNumber)) {
			throw new LdapInvalidDnException("Invalid phone number");
		}
		Dn searchBase = new Dn("ou=people,c=mycountry");
		String searchFilter = "(&(objectClass=organizationalPerson)(objectClass=inetOrgPerson)(objectClass=person)(mobile={0}))";
		LdapContext context = getContext();
		NamingEnumeration<SearchResult> searchResult = context.search(searchBase.getName(), searchFilter,
				new String[]{mobileNumber},new SearchControls());
		if (!searchResult.hasMore()) {
			throw new AuthManagerException("ADMN-ACM-MOB-NOT-FOUND", "Mobile is registered/not present");
		}
		context.close();
		return searchResult;
	}

	@Override
	public ValidationResponseDto validateUserName(String userId) {
		ValidationResponseDto validationResponseDto = new ValidationResponseDto();
		try {
			NamingEnumeration<SearchResult> searchResult = getUserDetailSearchResult(userId);
			while (searchResult.hasMore()) {
				Attributes attributes = searchResult.next().getAttributes();
				if (attributes.get("isActive") == null) {
					throw new AuthManagerException(AuthErrorCode.IS_ACTIVE_FLAG_NOT_FOUND.getErrorCode(),
							AuthErrorCode.IS_ACTIVE_FLAG_NOT_FOUND.getErrorMessage());
				}
				String isActive = (String) attributes.get("isActive").get();
				if (isActive.equalsIgnoreCase("true")) {
					validationResponseDto.setStatus("VALID");
				} else {
					validationResponseDto.setStatus("INVALID");
				}
			}

		} catch (NamingException e) {

			throw new AuthManagerException(AuthErrorCode.NAMING_EXCEPTION.getErrorCode(),
					AuthErrorCode.NAMING_EXCEPTION.getErrorMessage());
		} catch (LdapInvalidDnException e) {
			throw new AuthManagerException(AuthErrorCode.INVALID_DN.getErrorCode(),
					AuthErrorCode.INVALID_DN.getErrorMessage());
		}

		return validationResponseDto;
	}

	private NamingEnumeration<SearchResult> getUserDetailSearchResult(String userId)
			throws NamingException, LdapInvalidDnException {
		LdapContext context = getContext();
		userId = escapeLDAPValue(userId);
		Dn searchBase = new Dn("uid=" + userId + ",ou=people,c=mycountry");
		SearchControls searchControls = new SearchControls();
		searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		NamingEnumeration<SearchResult> searchResult = context.search(searchBase.getName(),
				"(&(objectClass=organizationalPerson)(objectClass=inetOrgPerson)(objectClass=person))", searchControls);
		if (!searchResult.hasMore()) {
			throw new AuthManagerException(AuthErrorCode.USER_NOT_FOUND.getErrorCode(),
					AuthErrorCode.USER_NOT_FOUND.getErrorMessage());
		}
		context.close();
		return searchResult;
	}

	private void closeContext(LdapContext context) {
		try {
			Objects.requireNonNull(context, "context not initialized");
			context.close();
		} catch (NamingException e) {
			throw new AuthManagerException(AuthErrorCode.NAMING_EXCEPTION.getErrorCode(),
					AuthErrorCode.NAMING_EXCEPTION.getErrorMessage());
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * io.mosip.kernel.auth.repository.DataStore#getUserDetailBasedOnUid(java.util.
	 * List)
	 */
	@Override
	public UserDetailsResponseDto getUserDetailBasedOnUid(List<String> userIds) {
		UserDetailsDto userDetailsDto = null;
		List<UserDetailsDto> userDetails = new ArrayList<>();
		UserDetailsResponseDto userDetailsResponseDto = new UserDetailsResponseDto();
		try {
			for (String userId : userIds) {

				NamingEnumeration<SearchResult> searchResult = getSearchResultBasedOnId(userId);
				while (searchResult.hasMore()) {
					SearchResult result = searchResult.next();
					userDetailsDto = setUserDetail(result);
					userDetailsDto.setUserId(userId);
					String rolesAsString = getRolesBasedOnUid(userId);
					userDetailsDto.setRole(rolesAsString);
					userDetails.add(userDetailsDto);
					break;
				}
			}
		} catch (NamingException e) {
			throw new AuthManagerException(AuthErrorCode.NAMING_EXCEPTION.getErrorCode(),
					AuthErrorCode.NAMING_EXCEPTION.getErrorMessage() + "" + e.getCause());
		} catch (LdapInvalidDnException e) {
			throw new AuthManagerException(AuthErrorCode.INVALID_DN.getErrorCode(),
					AuthErrorCode.INVALID_DN.getErrorMessage() + " " + e.getCause());
		}
		userDetailsResponseDto.setUserDetails(userDetails);
		return userDetailsResponseDto;
	}

	/**
	 * 
	 * @param userId - userId
	 * @return {@link NamingEnumeration}
	 * @throws NamingException
	 * @throws LdapInvalidDnException
	 */
	private NamingEnumeration<SearchResult> getSearchResultBasedOnId(String userId)
			throws NamingException, LdapInvalidDnException {

		LdapContext context = getContext();
		userId = escapeLDAPValue(userId);
		Dn searchBase = new Dn("uid=" + userId + ",ou=people,c=mycountry");
		SearchControls searchControls = new SearchControls();
		NamingEnumeration<SearchResult> searchResult = null;

		searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		searchResult = context.search(searchBase.getName(),
				"(&(objectClass=organizationalPerson)(objectClass=inetOrgPerson)(objectClass=person))", searchControls);

		context.close();
		return searchResult;
	}

	/**
	 * Sets the user detail.
	 *
	 * @param result the result
	 * @return the user details dto
	 * @throws NamingException the naming exception
	 */
	private UserDetailsDto setUserDetail(SearchResult result) throws NamingException {
		UserDetailsDto userDetailsDto = new UserDetailsDto();

		if (result.getAttributes().get(LdapConstants.USER_PASSWORD) != null) {
			userDetailsDto.setUserPassword((byte[]) result.getAttributes().get(LdapConstants.USER_PASSWORD).get());
		}
		userDetailsDto.setMobile((String) result.getAttributes().get(LdapConstants.MOBILE).get());
		userDetailsDto.setMail((String) result.getAttributes().get(LdapConstants.MAIL).get());
		userDetailsDto.setName((String) result.getAttributes().get(LdapConstants.CN).get());
		if (result.getAttributes().get(LdapConstants.FIRST_NAME) != null) {
			userDetailsDto.setFirstName((String) result.getAttributes().get(LdapConstants.FIRST_NAME).get());
		}
		if (result.getAttributes().get(LdapConstants.LAST_NAME) != null) {
			userDetailsDto.setLastName((String) result.getAttributes().get(LdapConstants.FIRST_NAME).get());
		}
		if (result.getAttributes().get(LdapConstants.GENDER_CODE) != null) {
			userDetailsDto.setGender((String) result.getAttributes().get(LdapConstants.GENDER_CODE).get());
		}
		if (result.getAttributes().get(LdapConstants.IS_ACTIVE) != null) {
			userDetailsDto
					.setActive(Boolean.valueOf((String) result.getAttributes().get(LdapConstants.IS_ACTIVE).get()));
		}
		if (result.getAttributes().get(LdapConstants.DOB) != null) {
			String dob = (String) result.getAttributes().get(LdapConstants.DOB).get();
			LocalDate dobInLocalDate = LocalDate.parse(dob);
			userDetailsDto.setDateOfBirth(dobInLocalDate);
		}
		if (result.getAttributes().get(LdapConstants.RID) != null) {
			userDetailsDto.setRId((String) result.getAttributes().get(LdapConstants.RID).get());
		}

		return userDetailsDto;
	}

	/**
	 * TBD pagenation
	 * 
	 * @param list
	 * @param pageSize
	 * @return
	 */
	public Map<Object, Object> getPagenatedMap(List<UserDetailsDto> list, int pageSize) {
		return IntStream.iterate(0, i -> i + pageSize).limit((list.size() + pageSize - 1) / pageSize).boxed().collect(
				Collectors.toMap(i -> i / pageSize, i -> list.subList(i, Math.min(i + pageSize, list.size()))));
	}

	/**
	 * Gets the roles based on uid.
	 *
	 * @param uid     the uid
	 * @param context the context
	 * @return the roles based on uid
	 * @throws LdapInvalidDnException the ldap invalid dn exception
	 * @throws NamingException        the naming exception
	 */
	private String getRolesBasedOnUid(String uid) throws LdapInvalidDnException, NamingException {
		LdapContext context = getContext();
		Dn searchBase = new Dn("ou=roles,c=mycountry");
		uid = escapeLDAPValue(uid);
		String searchFilter = "(&(objectClass=organizationalRole)(roleOccupant=uid=" + uid + ",ou=people,c=mycountry))";
		NamingEnumeration<SearchResult> searchResultRoles = context.search(searchBase.getName(), searchFilter,
				new SearchControls());
		Set<String> roles = new HashSet<>();
		while (searchResultRoles.hasMore()) {
			Attributes attributeRoles = searchResultRoles.next().getAttributes();
			roles.add((String) attributeRoles.get("cn").get());
		}
		context.close();
		try {
			return convertRolesToString(roles);
		} catch (Exception e) {
			throw new AuthManagerException(AuthErrorCode.RUNTIME_EXCEPTION.getErrorCode(),
					AuthErrorCode.RUNTIME_EXCEPTION.getErrorMessage());
		}
	}

	/**
	 * Validates the mobile number
	 * 
	 * @param mobileNumber mobile number
	 * 
	 */
	private boolean IsValidPhoneNumber(String mobileNumber) {

		Pattern phonePattern = Pattern.compile("^\\+(?:[0-9] ?){6,14}[0-9]$");
		Matcher phoneMatcher = phonePattern.matcher(mobileNumber);
		if (phoneMatcher.matches()) {
			return true;
		}
		return false;
	}

	/**
	 * Escape the ldap vallue string. The method is not designed to escape the
	 * entire filter. So please pass only the value that you want to escape.
	 * 
	 * @param ldapString ldap filter string
	 */
	private String escapeLDAPValue(String ldapString) {
		if (null == ldapString)
			return "";
		try {
			// Fix as per
			// https://stackoverflow.com/questions/31309673/parse-ldap-filter-to-escape-special-characters
			StringBuilder finalLdapString = new StringBuilder(ldapString.length());
			for (byte ldapCharacter : ldapString.getBytes("UTF-8")) {
				if (ldapCharacter == '\\') {
					finalLdapString.append("\\5c");
				} else if (ldapCharacter == '*') {
					finalLdapString.append("\\2a");
				} else if (ldapCharacter == '(') {
					finalLdapString.append("\\28");
				} else if (ldapCharacter == ')') {
					finalLdapString.append("\\29");
				} else if (ldapCharacter == 0) {
					finalLdapString.append("\\00");
				} else if ((ldapCharacter & 0xff) > 127) {
					finalLdapString.append("\\").append(to2CharHexString((ldapCharacter & 0xff)));
				} else {
					finalLdapString.append((char) ldapCharacter);
				}
			}
			return finalLdapString.toString();
		} catch (Exception ex) {
			LOGGER.warn("Invalid ldap string " + ldapString + " so sending back empty string ");
			return "";
		}

	}

	private String to2CharHexString(int hexValue) {
		String hexCharacter = Integer.toHexString(hexValue & 0xff);
		if (hexCharacter.length() == 1)
			return "0" + hexCharacter;
		else
			return hexCharacter;
	}

	@Override
	public IndividualIdDto getIndividualIdFromUserId(String userId, String realmID) {
		// TODO code cleaup
		throw new UnsupportedOperationException("This openeration is not supported in local profile for now");
	}

	@Override
	public MosipUserListDto getListOfUsersDetails(String realmId, String roleName, int pageStart, int pageFetch,
			String email, String firstName, String lastName, String username, String search) {
		throw new UnsupportedOperationException("This openeration is not supported");
	}

}
