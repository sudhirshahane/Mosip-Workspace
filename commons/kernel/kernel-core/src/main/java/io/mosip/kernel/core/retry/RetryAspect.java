package io.mosip.kernel.core.retry;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import io.mosip.kernel.core.util.RetryUtil;

/**
 * The Aspect Class RetryAspect that applies the retry mechanism on methods with
 *  {@link WithRetry} annotation.
 * 
 * @author Loganathan Sekar
 */
@Aspect
@Component
public class RetryAspect {

	/** The retry util. */
	@Autowired
	private RetryUtil retryUtil;

	/**
	 * With retry methods.
	 */
	@Pointcut("@annotation(WithRetry)")
	public void withRetryMethods() {
	}

	/**
	 * Process methods with retry.
	 *
	 * @param pjp the pjp
	 * @return the object
	 * @throws Throwable the throwable
	 */
	@Around("withRetryMethods()")
	public Object processMethodsWithRetry(final ProceedingJoinPoint pjp) throws Throwable {
		return retryUtil.<Object, Throwable>doWithRetry(() -> pjp.proceed());
	}
}
