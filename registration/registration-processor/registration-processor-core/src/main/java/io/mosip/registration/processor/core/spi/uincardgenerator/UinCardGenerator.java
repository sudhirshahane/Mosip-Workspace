package io.mosip.registration.processor.core.spi.uincardgenerator;

import java.io.InputStream;

import io.mosip.registration.processor.core.constant.UinCardType;
import io.mosip.registration.processor.core.exception.ApisResourceAccessException;

/**
 * The Interface UinCardGenerator.
 * 
 * @author M1048358 Alok
 *
 * @param <I>
 *            the generic type
 */
public interface UinCardGenerator<I> {

	/**
	 * Generate uin card.
	 *
	 * @param in
	 *            the in
	 * @param type
	 *            the type
	 * @param password
	 *            the password
	 * @return the i
	 */
	public I generateUinCard(InputStream in, UinCardType type, String password) throws ApisResourceAccessException;
}
