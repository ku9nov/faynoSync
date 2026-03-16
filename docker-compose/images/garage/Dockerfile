FROM dxflrs/garage:v2.2.0 AS garage

FROM alpine:3.21

COPY --from=garage /garage /garage
COPY docker-compose/scripts/garage-entrypoint.sh /usr/local/bin/garage-entrypoint.sh

RUN ln -s /garage /usr/local/bin/garage \
    && chmod +x /garage /usr/local/bin/garage-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/garage-entrypoint.sh"]
