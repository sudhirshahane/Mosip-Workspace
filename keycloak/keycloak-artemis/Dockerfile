FROM docker.io/bitnami/minideb:buster
LABEL maintainer "Bitnami <containers@bitnami.com>"

ENV HOME="/" \
    OS_ARCH="amd64" \
    OS_FLAVOUR="debian-10" \
    OS_NAME="linux"

ARG JAVA_EXTRA_SECURITY_DIR="/bitnami/java/extra-security"

COPY prebuildfs /
RUN chmod +x /usr/sbin/install_packages
# Install required system packages and dependencies
RUN install_packages acl ca-certificates curl gzip libaio1 libc6 procps rsync tar zlib1g
RUN . /opt/bitnami/scripts/libcomponent.sh && component_unpack "wait-for-port" "1.0.1-10" --checksum 35c818ba3f4b5aae905959bc7d3a5e81fc63786e3c662b604612c0aa7fcda8fd
RUN . /opt/bitnami/scripts/libcomponent.sh && component_unpack "java" "11.0.14-7" --checksum 900545c4f346a0ece8abf2caf64fd9d4ab7514967d4614d716bf7362b24f828b
RUN . /opt/bitnami/scripts/libcomponent.sh && component_unpack "keycloak" "16.1.1-8" --checksum c432a2b3551a40e48b77f63257def52e9556c2b6ffa989e7eb6847ad87fdd9db
RUN . /opt/bitnami/scripts/libcomponent.sh && component_unpack "gosu" "1.14.0-7" --checksum d6280b6f647a62bf6edc74dc8e526bfff63ddd8067dcb8540843f47203d9ccf1
RUN apt-get update && apt-get upgrade -y && \
    rm -r /var/lib/apt/lists /var/cache/apt/archives
RUN chmod g+rwX /opt/bitnami

COPY ./theme/base /opt/bitnami/keycloak/themes/base

COPY ./theme/mosip /opt/bitnami/keycloak/themes/mosip

COPY ./standalone/deployments/* /opt/bitnami/keycloak/standalone/deployments

COPY rootfs /
RUN chmod +x /opt/bitnami/scripts/keycloak/postunpack.sh
RUN chmod +x /opt/bitnami/scripts/java/postunpack.sh

RUN /opt/bitnami/scripts/java/postunpack.sh
RUN /opt/bitnami/scripts/keycloak/postunpack.sh
ENV APP_VERSION="16.1.1" \
    BITNAMI_APP_NAME="keycloak" \
    JAVA_HOME="/opt/bitnami/java" \
    PATH="/opt/bitnami/common/bin:/opt/bitnami/java/bin:/opt/bitnami/keycloak/bin:$PATH"

RUN chmod +x /opt/bitnami/scripts/keycloak/entrypoint.sh
RUN chmod +x /opt/bitnami/scripts/keycloak/setup.sh
RUN chmod +x /opt/bitnami/scripts/keycloak/run.sh
USER 1001
ENTRYPOINT [ "/opt/bitnami/scripts/keycloak/entrypoint.sh" ]
CMD [ "/opt/bitnami/scripts/keycloak/run.sh" ]
