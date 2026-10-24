FROM ubuntu:24.04

RUN ["apt-get", "update"]
RUN ["apt-get", "install", "-y", "--no-install-recommends", "openssh-server", "ca-certificates"]
RUN ["useradd", "--create-home", "--shell", "/bin/sh", "secmon"]
RUN ["install", "-d", "-m", "0700", "-o", "secmon", "-g", "secmon", "/home/secmon/.ssh"]
RUN ["install", "-d", "-m", "0755", "/run/sshd"]

COPY secmon-agent /usr/local/bin/secmon-agent
COPY sshd_config /etc/ssh/sshd_config
RUN ["chmod", "0755", "/usr/local/bin/secmon-agent"]

EXPOSE 22
ENTRYPOINT ["/usr/sbin/sshd", "-D", "-e"]
