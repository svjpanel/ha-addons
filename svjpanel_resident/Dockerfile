# Single source of truth for the public svjpanel/ha-addons image. Supervisor passes BUILD_FROM from build.yaml,
# which must pin an immutable digest (name@sha256:...); the build fails without it.
ARG BUILD_FROM
FROM ${BUILD_FROM}
ARG BUILD_FROM
RUN test "${BUILD_FROM#*@sha256:}" != "${BUILD_FROM}"
WORKDIR /app
COPY resident_addon /app/resident_addon
# No USER: /data/options.json is root-owned under Supervisor and unreadable for "nobody".
CMD ["python", "-m", "resident_addon"]
