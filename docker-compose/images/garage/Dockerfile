FROM dxflrs/garage:v2.5.0@sha256:677e5b758e4425a325b811c425c026bf35a4bf42f7ddbaa773de3f4fd779a5a5 AS garage

FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a

COPY --from=garage /garage /garage
COPY docker-compose/scripts/garage-entrypoint.sh /usr/local/bin/garage-entrypoint.sh

RUN ln -s /garage /usr/local/bin/garage \
    && chmod +x /garage /usr/local/bin/garage-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/garage-entrypoint.sh"]
