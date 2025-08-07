FROM jetty:12-jdk21

ARG JETTY_USER=jetty
ARG JETTY_GROUP=jetty
ARG JETTY_BASE=/jetty-base

RUN mkdir -p ${JETTY_BASE}/webapps/nomulus && \
    unzip ${JETTY_BASE}/webapps/nomulus.war -d ${JETTY_BASE}/webapps/nomulus && \
    rm ${JETTY_BASE}/webapps/nomulus.war && \
    chown -R ${JETTY_USER}:${JETTY_GROUP} ${JETTY_BASE}/webapps/nomulus

# Add the entire pre-built jetty-base from your build stage
ADD --chown=${JETTY_USER}:${JETTY_GROUP} build/jetty-base ${JETTY_BASE}
ADD --chown=${JETTY_USER}:${JETTY_GROUP} start.sh /
ADD --chown=${JETTY_USER}:${JETTY_GROUP} logging.properties /

EXPOSE 8080
ENTRYPOINT ["/bin/sh", "/start.sh"]
