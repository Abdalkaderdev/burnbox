FROM node:22-bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends strace python3 make git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh dnsstub.py /opt/burnbox/
COPY home/ /opt/burnbox/home/
RUN chmod 0755 /opt/burnbox/entrypoint.sh && chmod -R a+rX /opt/burnbox
ENTRYPOINT ["/opt/burnbox/entrypoint.sh"]
