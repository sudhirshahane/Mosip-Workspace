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

import consolidatorService.util;

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

# Kafka topic which is stores consolidated websub subscribers for this server
public configurable string[] META_TOPICS = [REGISTERED_WEBSUB_TOPICS_TOPIC,CONSOLIDATED_WEBSUB_TOPICS_TOPIC,WEBSUB_SUBSCRIBERS_TOPIC,CONSOLIDATED_WEBSUB_SUBSCRIBERS_TOPIC];


# The interval in which Kafka consumers wait for new messages
public configurable decimal POLLING_INTERVAL = 10;

# The period in which Kafka close method waits to complete
public configurable decimal GRACEFUL_CLOSE_PERIOD = 5;

public final string CONSTRUCTED_CONSUMER_ID = util:generateRandomString();

public final string CURRENT_WORKING_DIR = "user.dir";

# The disk space threshold for healthcheck
public configurable int DISK_SPACE_THRESHOLD = 10485760;

# The port that is used to start the consolidator
public configurable int CONSOLIDATOR_PORT = 9192;

# consolidator health endpoint
public configurable string CONSOLIDATOR_HEALTH_ENDPOINT = "/consolidator/actuator/health";
