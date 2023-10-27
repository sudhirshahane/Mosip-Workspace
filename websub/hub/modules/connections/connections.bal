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

import ballerinax/kafka;
import kafkaHub.config;

// Producer which persist the current in-memory state of the Hub 
kafka:ProducerConfiguration statePersistConfig = {
    clientId: "state-persist",
    acks: "1",
    retryCount: 3
};
public final kafka:Producer statePersistProducer = check new (config:KAFKA_BOOTSTRAP_NODE, statePersistConfig);

// Consumer which reads the persisted subscriber details
kafka:ConsumerConfiguration subscribersConsumerConfig = {
    groupId: "consolidated-websub-subscribers-group-" + config:CONSTRUCTED_SERVER_ID,
    offsetReset: "earliest",
    topics: [ config:CONSOLIDATED_WEBSUB_SUBSCRIBERS_TOPIC ]
};
public final kafka:Consumer subscribersConsumer = check new (config:KAFKA_BOOTSTRAP_NODE, subscribersConsumerConfig);

// Consumer which reads the persisted subscriber details
kafka:ConsumerConfiguration registeredTopicsConsumerConfig = {
    groupId: "consolidated--websub-topics-group-" + config:CONSTRUCTED_SERVER_ID,
    offsetReset: "earliest",
    topics: [ config:CONSOLIDATED_WEBSUB_TOPICS_TOPIC ]
};
public final kafka:Consumer registeredTopicsConsumer = check new (config:KAFKA_BOOTSTRAP_NODE, registeredTopicsConsumerConfig);

# Creates a `kafka:Consumer` for a subscriber.
# 
# + message - The subscription details
# + return - `kafka:Consumer` if succcessful or else `error`
public isolated function createMessageConsumer(string topicName, string groupName) returns kafka:Consumer|error {
    kafka:ConsumerConfiguration consumerConfiguration = {
        groupId: groupName,
        topics: [topicName],
        autoCommit: false,
        maxPollRecords: config:KAFKA_CONSUMER_MAX_POLL_RECORDS,
        fetchMaxBytes: config:KAFKA_CONSUMER_FETCH_MAX_BYTES,
        maxPartitionFetchBytes: config:KAFKA_CONSUMER_MAX_PARTITION_FETCH_BYTES
    };
    return check new (config:KAFKA_BOOTSTRAP_NODE, consumerConfiguration);  
}
