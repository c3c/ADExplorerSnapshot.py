# syntax=docker/dockerfile:1

# Use Python 3.10 to avoid 3.11 incompatability
# See https://github.com/ly4k/Certipy/issues/108
ARG VERSION=3.10-alpine
FROM python:$VERSION

RUN <<-EOF
    echo "@testing http://dl-cdn.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories
    apk add git bash cmake build-base linux-headers python3-dev py3-capstone py3-psutil py3-unicorn@testing
EOF

WORKDIR /usr/src/app

COPY . .

RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT [ "python", "ADExplorerSnapshot.py" ]
CMD [ "--help" ]
