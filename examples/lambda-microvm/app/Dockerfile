FROM public.ecr.aws/lambda/microvms:al2023-minimal
RUN dnf install -y python3.12 python3.12-pip util-linux bash tar gzip && dnf clean all
RUN python3.12 -m pip install --no-cache-dir boto3==1.42.61 aws-bedrock-token-generator==1.1.0
WORKDIR /opt/demo
COPY . .
RUN python3.12 install.py && mkdir -m 700 /work
EXPOSE 8080 9000
CMD ["/usr/bin/python3.12", "/opt/demo/app.py"]
