package io.mosip.kernel.core.util;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.stereotype.Component;

import io.mosip.kernel.core.function.ConsumerWithThrowable;
import io.mosip.kernel.core.function.FunctionWithThrowable;
import io.mosip.kernel.core.function.RunnableWithThrowable;
import io.mosip.kernel.core.function.SupplierWithThrowable;

/**
 * The RetryUtil - an Utility to invoke any method / expression with retries as per the
 * configuration.
 */
@Component
public class RetryUtil {
	
	/** The retry template. */
	@Autowired
	private RetryTemplate retryTemplate;
	
	/**
	 * Invoke the function with retry.
	 *
	 * @param <R> the generic type
	 * @param <T> the generic type
	 * @param <E> the element type
	 * @param func the {@link FunctionWithThrowable} instance or its lambda expression
	 * @param t the t
	 * @return the r
	 * @throws E the e
	 */
	public <R, T, E extends Throwable> R doWithRetry(FunctionWithThrowable<R, T, E> func, T t) throws E {
		return doProcessWithRetry(func, t);
	}
	
	/**
	 * Invoke the supplier with retry.
	 *
	 * @param <R> the generic type
	 * @param <E> the element type
	 * @param func the {@link SupplierWithThrowable} instance or its lambda expression
	 * @return the r
	 * @throws E the e
	 */
	public <R, E extends Throwable> R doWithRetry(SupplierWithThrowable<R, E> func) throws E {
		return doProcessWithRetry(t -> func.get(), null);
	}
	
	/**
	 * Invoke the consumer with retry.
	 *
	 * @param <T> the generic type
	 * @param <E> the element type
	 * @param func the {@link ConsumerWithThrowable} instance or its lambda expression
	 * @param t the t
	 * @throws E the e
	 */
	public <T, E extends Throwable> void doWithRetry(ConsumerWithThrowable<T, E> func,T t) throws E {
		this.<Void, T, E>doProcessWithRetry(t1 -> {
			func.accept(t1);
			return null;
		},t );
	}
	
	/**
	 * Invoke the supplier with retry.
	 *
	 * @param <E> the element type
	 * @param func the {@link RunnableWithThrowable} instance or its lambda expression
	 * @throws E the e
	 */
	public <E extends Throwable> void doWithRetry(RunnableWithThrowable<E> func) throws E {
		this.<Void, Void, E>doProcessWithRetry(t -> {
			func.run();
			return null;
		}, null);
	}
	
	/**
	 * Do process with retry.
	 *
	 * @param <R> the generic type
	 * @param <T> the generic type
	 * @param <E> the element type
	 * @param func the func
	 * @param t the t
	 * @return the r
	 * @throws E the e
	 */
	private <R, T, E extends Throwable> R doProcessWithRetry(FunctionWithThrowable<R, T, E> func, T t) throws E {
		R result = retryTemplate.execute(context -> func.apply(t));
		return result;
	}

}
