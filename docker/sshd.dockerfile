FROM debian:bookworm-slim

RUN mkdir -p /var/run/sshd

# Install run dependencies
RUN apt-get -yq update && apt-get -yq install openssh-server openssl socat netcat-openbsd sudo

COPY --chmod=700 sshd_config /etc/ssh/

RUN useradd -ms /bin/bash passwordlessuser
RUN passwd -d passwordlessuser

RUN useradd -ms /bin/bash -p "$(openssl passwd -6 Password12345)" passworduser

RUN useradd -ms /bin/bash -p "$(openssl passwd -6 ChangeMe123)" needspasswordchange
RUN passwd --expire needspasswordchange

