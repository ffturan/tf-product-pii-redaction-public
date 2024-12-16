#!/usr/bin/bash

podman build -t pii_redact:latest -f Dockerfile .
podman tag pii_redact:latest 564400272142.dkr.ecr.us-east-1.amazonaws.com/lambda_image_to_text:latest
podman push 564400272142.dkr.ecr.us-east-1.amazonaws.com/lambda_image_to_text:latest

