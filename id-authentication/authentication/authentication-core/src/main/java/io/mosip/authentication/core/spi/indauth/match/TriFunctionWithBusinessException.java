package io.mosip.authentication.core.spi.indauth.match;

import io.mosip.authentication.core.exception.IdAuthenticationBusinessException;

/**
 * 
 * 
 * 
 * 
 * Functional interface to throw Business Exception
 * 
 * @author Dinesh Karuppiah.T
 */
@FunctionalInterface
public interface TriFunctionWithBusinessException<T, U, V, R> {

	/**
	 * Applies this function to the given arguments.
	 *
	 * @param t the first function argument
	 * @param u the second function argument
	 * @return the function result
	 * @throws IdAuthenticationBusinessException the id authentication business exception
	 */
	R apply(T t, U u, V v) throws IdAuthenticationBusinessException;

}