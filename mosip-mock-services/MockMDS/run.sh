#!/bin/sh

echo "Starting MOCK MDS service..."

nohup java -cp mock-mds-1.2.0.1-B1.jar:lib/* io.mosip.mock.sbi.test.TestMockSBI "mosip.mock.sbi.device.purpose=Registration" "mosip.mock.sbi.biometric.type=Biometric Device" > /tmp/mock_mds.log 2>&1 &

echo "Started MOCK MDS service."
