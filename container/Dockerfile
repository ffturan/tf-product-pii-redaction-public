FROM public.ecr.aws/lambda/python:3.12

# Install system dependencies
RUN dnf install -y poppler poppler-utils

# Copy requirements.txt
COPY requirements.txt /var/task

# Install the specified packages
RUN pip install -r requirements.txt --no-cache-dir

# Copy function code
COPY main.py /var/task

# Set the entrypoint for the Lambda function
CMD ["main.lambda_handler"]
