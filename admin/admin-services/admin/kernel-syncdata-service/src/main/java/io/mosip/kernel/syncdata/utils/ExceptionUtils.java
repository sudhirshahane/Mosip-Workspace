package io.mosip.kernel.syncdata.utils;

import java.util.Optional;
import java.util.stream.Stream;

/**
 * This class is used to get the Exception related functionalities.
 * 
 * @author Urvil Joshi
 * @author Bal Vikash Sharma
 * @author Sagar Mahapatra
 * @author Ritesh Sinha
 * @author Dharmesh Khandelwal
 * 
 * @since 1.0.0
 */
public final class ExceptionUtils {
	/**
	 * Constructor for ExceptionUtils class.
	 */
	private ExceptionUtils() {
		super();
	}

	/**
	 * Method to find the root cause of the exception.
	 * 
	 * @param exception the exception.
	 * @return the root cause.
	 */
	public static String parseException(Throwable exception) {
		Optional<Throwable> rootCause = Stream.iterate(exception, Throwable::getCause)
				.filter(element -> element.getCause() == null).findFirst();
		String cause = rootCause.isPresent() ? rootCause.get().getMessage() : exception.getMessage();
		return " " + cause;
	}
	public static Object neutralizeParam(Object param) {
		if(param != null && param instanceof String)
			return ((String) param).replaceAll("[\n\r\t]", "_");

		return param;
	}
}
