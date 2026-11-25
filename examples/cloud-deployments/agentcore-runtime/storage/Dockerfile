FROM public.ecr.aws/docker/library/python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
WORKDIR /opt/runtime-storage
COPY bin/ ./bin/
COPY server.py workload binary-manifest.json ./
ENV PYTHONUNBUFFERED=1 STORAGE_PATH=/mnt/storage
USER 1000:1000
EXPOSE 8080
CMD ["python3", "/opt/runtime-storage/server.py"]
