# Build stage
FROM python:3.11-slim AS builder

ENV VENV_PATH=/opt/venv

RUN python -m venv ${VENV_PATH}
RUN ${VENV_PATH}/bin/pip install --upgrade pip

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN ${VENV_PATH}/bin/pip install --no-cache-dir -r /app/requirements.txt

# Runtime stage
FROM python:3.11-alpine

ENV VENV_PATH=/opt/venv
ENV PATH="${VENV_PATH}/bin:${PATH}"

RUN addgroup -S specter && adduser -S specter -G specter
RUN apk add --no-cache libpcap

WORKDIR /app
COPY --from=builder ${VENV_PATH} ${VENV_PATH}
COPY . /app

RUN chown -R specter:specter /app
USER specter

ENTRYPOINT ["python", "main.py"]
