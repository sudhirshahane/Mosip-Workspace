package io.mosip.kernel.clientcrypto.service.impl;

import io.mosip.kernel.clientcrypto.constant.ClientType;
import io.mosip.kernel.clientcrypto.dto.*;
import io.mosip.kernel.clientcrypto.service.spi.ClientCryptoManagerService;
import io.mosip.kernel.clientcrypto.util.ClientCryptoUtils;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.keymanagerservice.logger.KeymanagerLogger;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * @author Anusha Sunkada
 * @since 1.1.2
 */
@Service
public class ClientCryptoManagerServiceImpl implements ClientCryptoManagerService {

    private static final Logger LOGGER = KeymanagerLogger.getLogger(ClientCryptoManagerServiceImpl.class);

    @Autowired
    private ClientCryptoFacade clientCryptoFacade;

    @Override
    public TpmSignResponseDto csSign(TpmSignRequestDto tpmSignRequestDto) {
        byte[] signedData = clientCryptoFacade.getClientSecurity().signData(
                ClientCryptoUtils.decodeBase64Data(tpmSignRequestDto.getData()));
        TpmSignResponseDto tpmSignResponseDto = new TpmSignResponseDto();
        tpmSignResponseDto.setData(CryptoUtil.encodeToURLSafeBase64(signedData));
        return tpmSignResponseDto;
    }

    @Override
    public TpmSignVerifyResponseDto csVerify(TpmSignVerifyRequestDto tpmSignVerifyRequestDto) {
        boolean result = clientCryptoFacade.validateSignature(tpmSignVerifyRequestDto.getClientType() == null ?
                        ClientType.LOCAL : tpmSignVerifyRequestDto.getClientType(),
                ClientCryptoUtils.decodeBase64Data(tpmSignVerifyRequestDto.getPublicKey()),
                ClientCryptoUtils.decodeBase64Data(tpmSignVerifyRequestDto.getSignature()),
                ClientCryptoUtils.decodeBase64Data(tpmSignVerifyRequestDto.getData()));
        TpmSignVerifyResponseDto tpmSignVerifyResponseDto = new TpmSignVerifyResponseDto();
        tpmSignVerifyResponseDto.setVerified(result);
        return tpmSignVerifyResponseDto;
    }

    @Override
    public TpmCryptoResponseDto csEncrypt(TpmCryptoRequestDto tpmCryptoRequestDto) {
        byte[] cipher = clientCryptoFacade.encrypt(tpmCryptoRequestDto.getClientType() == null ?
                ClientType.LOCAL : tpmCryptoRequestDto.getClientType(),
                ClientCryptoUtils.decodeBase64Data(tpmCryptoRequestDto.getPublicKey()),
                ClientCryptoUtils.decodeBase64Data(tpmCryptoRequestDto.getValue()));
        TpmCryptoResponseDto tpmCryptoResponseDto = new TpmCryptoResponseDto();
        tpmCryptoResponseDto.setValue(CryptoUtil.encodeToURLSafeBase64(cipher));
        return tpmCryptoResponseDto;
    }

    @Override
    public TpmCryptoResponseDto csDecrypt(TpmCryptoRequestDto tpmCryptoRequestDto) {
        byte[] plainData = clientCryptoFacade.decrypt(ClientCryptoUtils.decodeBase64Data(tpmCryptoRequestDto.getValue()));
        TpmCryptoResponseDto tpmCryptoResponseDto = new TpmCryptoResponseDto();
        tpmCryptoResponseDto.setValue(CryptoUtil.encodeToURLSafeBase64(plainData));
        return tpmCryptoResponseDto;
    }

    @Override
    public PublicKeyResponseDto getSigningPublicKey(PublicKeyRequestDto publicKeyRequestDto) {
        PublicKeyResponseDto publicKeyResponseDto = new PublicKeyResponseDto();
        publicKeyResponseDto.setPublicKey(CryptoUtil.encodeToURLSafeBase64(clientCryptoFacade.getClientSecurity().
                getSigningPublicPart()));
        return publicKeyResponseDto;
    }

    @Override
    public PublicKeyResponseDto getEncPublicKey(PublicKeyRequestDto publicKeyRequestDto) {
        PublicKeyResponseDto publicKeyResponseDto = new PublicKeyResponseDto();
        publicKeyResponseDto.setPublicKey(CryptoUtil.encodeToURLSafeBase64(clientCryptoFacade.getClientSecurity().
                getEncryptionPublicPart()));
        return publicKeyResponseDto;
    }
}
