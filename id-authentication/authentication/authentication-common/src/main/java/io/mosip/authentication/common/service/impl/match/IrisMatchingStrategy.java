package io.mosip.authentication.common.service.impl.match;

import java.util.Map;

import io.mosip.authentication.core.constant.IdAuthenticationErrorConstants;
import io.mosip.authentication.core.exception.IdAuthenticationBusinessException;
import io.mosip.authentication.core.spi.indauth.match.TriFunctionWithBusinessException;
import io.mosip.authentication.core.spi.indauth.match.MatchFunction;
import io.mosip.authentication.core.spi.indauth.match.MatchingStrategy;
import io.mosip.authentication.core.spi.indauth.match.MatchingStrategyType;

/**
 * The Enum IrisMatchingStrategy.
 * 
 * @author Arun Bose S
 */
public enum IrisMatchingStrategy implements MatchingStrategy {

	@SuppressWarnings("unchecked")
	PARTIAL(MatchingStrategyType.PARTIAL, (Object reqInfo, Object entityInfo, Map<String, Object> props) -> {

		if (reqInfo instanceof Map && entityInfo instanceof Map) {
			Object object = props.get(IdaIdMapping.IRIS.getIdname());
			if (object instanceof TriFunctionWithBusinessException) {
				TriFunctionWithBusinessException<Map<String, String>, 
					Map<String, String>, 
					Map<String, Object>, 
					Double> func = (TriFunctionWithBusinessException<Map<String, String>, 
							Map<String, String>, 
							Map<String, Object>, 
							Double>) object;
				return (int) func.apply((Map<String, String>) reqInfo, (Map<String, String>) entityInfo, props)
						.doubleValue();
			} else {
				throw new IdAuthenticationBusinessException(IdAuthenticationErrorConstants.BIO_MISMATCH.getErrorCode(),
						String.format(IdAuthenticationErrorConstants.BIO_MISMATCH.getErrorMessage(),
								BioAuthType.IRIS_IMG.getType()));
			}
		}
		return 0;
	});
	/** The matching strategy impl. */
	private MatchingStrategyImpl matchingStrategyImpl;

	/**
	 * Instantiates a new iris matching strategy.
	 *
	 * @param matchStrategyType the match strategy type
	 * @param matchFunction     the match function
	 */
	private IrisMatchingStrategy(MatchingStrategyType matchStrategyType, MatchFunction matchFunction) {
		matchingStrategyImpl = new MatchingStrategyImpl(matchStrategyType, matchFunction);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see io.mosip.authentication.core.spi.indauth.match.MatchingStrategy#
	 * getMatchingStrategy()
	 */
	@Override
	public MatchingStrategy getMatchingStrategy() {
		return matchingStrategyImpl;
	}

}
