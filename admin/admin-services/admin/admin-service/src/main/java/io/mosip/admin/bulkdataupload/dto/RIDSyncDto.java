package io.mosip.admin.bulkdataupload.dto;

import lombok.Data;

import java.math.BigInteger;


@Data
public class RIDSyncDto {
    private String langCode;
    private String registrationId;
    private String packetId;
    private String additionalInfoReqId;
    private String registrationType;
    private String packetHashValue;
    private BigInteger packetSize;
    private String supervisorStatus;
    private String supervisorComment;
    private String name;
    private String phone;
    private String email;
}
