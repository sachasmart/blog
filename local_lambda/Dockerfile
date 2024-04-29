FROM public.ecr.aws/lambda/python:3.8
COPY requirements.txt /opt/requirements.txt
RUN pip install -r /opt/requirements.txt -t ${LAMBDA_TASK_ROOT}/
# COPY ./bootstrap.sh /var/runtime/bootstrap
# COPY ./bootstrap.py /var/runtime/bootstrap.py
# RUN chmod +x /var/runtime/bootstrap*