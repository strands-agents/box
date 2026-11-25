FROM public.ecr.aws/docker/library/python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
RUN groupadd --gid 1000 runtime-storage \
    && useradd --uid 1000 --gid 1000 --create-home --home-dir /home/runtime-storage runtime-storage
WORKDIR /opt/runtime-storage
COPY bin/ ./bin/
COPY server.py workload binary-manifest.json ./
ENV PYTHONUNBUFFERED=1 STORAGE_PATH=/mnt/storage HOME=/home/runtime-storage
USER 1000:1000
EXPOSE 8080
CMD ["python3", "/opt/runtime-storage/server.py"]
