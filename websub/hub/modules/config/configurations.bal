// Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
//
// WSO2 Inc. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

import kafkaHub.util;

# Flag to check whether to enable/disable security
public configurable boolean SECURITY_ON = true;

# Server ID is is used to uniquely identify each server 
# Each server must have a unique ID
public configurable string SERVER_ID = "server-1";

# IP and Port of the Kafka bootstrap node
public configurable string KAFKA_BOOTSTRAP_NODE = "localhost:9092";

# Kafka topic which will get notified for websub topic registration/deregistration
# All the hubs must be pointed to the same Kafka topic to notify websub topic registration/deregistration
public configurable string REGISTERED_WEBSUB_TOPICS_TOPIC = "registered-websub-topics";

# Kafka topic which stores consolidated websub topics for the hub
public configurable string CONSOLIDATED_WEBSUB_TOPICS_TOPIC = "consolidated-websub-topics";

# Kafka topic which will get notified for websub subscription/unsubscription
# All the hubs must be pointed to the same Kafka topic to notify websub subscription/unsubscription
public configurable string WEBSUB_SUBSCRIBERS_TOPIC = "registered-websub-subscribers";

# Kafka topic which is stores consolidated websub subscribers for this server
public configurable string CONSOLIDATED_WEBSUB_SUBSCRIBERS_TOPIC = "consolidated-websub-subscribers";

# The interval in which Kafka consumers wait for new messages
public configurable decimal POLLING_INTERVAL = 10;

# The period in which Kafka close method waits to complete
public configurable decimal GRACEFUL_CLOSE_PERIOD = 5;

# The port that is used to start the hub
public configurable int HUB_PORT = 9191;

# The period between retry requests
public configurable decimal MESSAGE_DELIVERY_RETRY_INTERVAL = 3;

# The maximum retry count
public configurable int MESSAGE_DELIVERY_COUNT = 3;

# The message delivery timeout
public configurable decimal MESSAGE_DELIVERY_TIMEOUT = 10;

# The base URL of IDP
public configurable string MOSIP_AUTH_BASE_URL = "https://host/";

# The token validation URL of IDP
public configurable string MOSIP_AUTH_VALIDATE_TOKEN_URL = "https://host/oauth2/token";

# The token validation URL of IDP
public configurable int DISK_SPACE_THRESHOLD = 10485760;

# The token validation URL of IDP
public configurable string PARTNER_USER_ID_PREFIX = "service-account-";

public final string CONSTRUCTED_SERVER_ID = string `${SERVER_ID}-${util:generateRandomString()}`;

public final string CURRENT_WORKING_DIR = "user.dir";

# The period between retry requests
public configurable decimal INTENT_VERIFICATION_RETRY_INTERVAL = 3;

# The maximum retry count
public configurable int INTENT_VERIFICATION_COUNT = 3;

# The period between retry requests
public configurable float INTENT_VERIFICATION_BACKOFF_FACTOR = 2.0;

# The maximum retry count
public configurable decimal INTENT_VERIFICATION_MAX_INTERVAL = 20;

# The maximum retry count
public configurable int KAFKA_CONSUMER_MAX_POLL_RECORDS = 50;

# The maximum retry count
public configurable int KAFKA_CONSUMER_FETCH_MAX_BYTES = 3145728;

# The maximum retry count
public configurable int KAFKA_CONSUMER_MAX_PARTITION_FETCH_BYTES = 524288;

# Kafka topic which is stores consolidated websub subscribers for this server
public configurable string META_TOPICS = "registered-websub-topics,consolidated-websub-topics,registered-websub-subscribers,consolidated-websub-subscribers";

# consolidator base url
public configurable string CONSOLIDATOR_BASE_URL = "http://websub-consolidator";

# consolidator health endpoint
public configurable string CONSOLIDATOR_HEALTH_ENDPOINT = "/consolidator/actuator/health";