FROM dxflrs/garage:v2.4.1@sha256:9c96caa2612d3411acc5b0e6701fb238dbfba33e533a6d7d3d811a4b12d0d020 AS garage

FROM alpine:3.21@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507

COPY --from=garage /garage /garage
COPY docker-compose/scripts/garage-entrypoint.sh /usr/local/bin/garage-entrypoint.sh

RUN ln -s /garage /usr/local/bin/garage \
    && chmod +x /garage /usr/local/bin/garage-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/garage-entrypoint.sh"]
