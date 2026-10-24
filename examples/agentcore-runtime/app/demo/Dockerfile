FROM public.ecr.aws/amazonlinux/amazonlinux@sha256:c07ab0773eddf9449c0994a87d8148300db98bdf8d8dad672a9dc26321c104fc
RUN dnf install -y python3.12 python3.12-pip shadow-utils && dnf clean all \
    && groupadd --gid 991 boxoperator \
    && useradd --uid 991 --gid 991 --create-home boxoperator
WORKDIR /app
RUN python3.12 -m pip install --no-cache-dir boto3==1.42.61 aws-bedrock-token-generator==1.1.0
COPY main.py claude_runtime.py manual_setup.py mcp_fixture.py box.toml policy.dw exercise.txt box.tar.gz box-package.json claude.tar.gz claude-package.json /app/
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
USER 991:991
EXPOSE 8080
ENTRYPOINT ["python3.12", "/app/main.py"]
