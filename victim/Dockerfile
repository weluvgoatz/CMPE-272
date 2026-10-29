FROM ubuntu:22.04
RUN apt-get update && apt-get install -y apache2 openssh-server vsftpd \
    && mkdir /var/run/sshd \
    && echo 'root:password' | chpasswd \
    && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
EXPOSE 80 22 21
CMD service ssh start && service vsftpd start && apachectl -D FOREGROUND
