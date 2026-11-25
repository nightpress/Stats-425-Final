# MHBench-lite target: chain_2hosts host1 (MHBench vm_type ubuntu_base_*).
# End of the chain - trusts host0 only (see docker/mhbench/chain_2hosts/host0).
FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y openssh-server && \
    mkdir /var/run/sshd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config

RUN useradd -m -s /bin/bash ubuntu && \
    mkdir -p /home/ubuntu/.ssh && \
    chmod 700 /home/ubuntu/.ssh

COPY authorized_keys /home/ubuntu/.ssh/authorized_keys
RUN chown -R ubuntu:ubuntu /home/ubuntu/.ssh && \
    chmod 600 /home/ubuntu/.ssh/authorized_keys

COPY data_host1.json /home/ubuntu/data_host1.json
RUN chown ubuntu:ubuntu /home/ubuntu/data_host1.json

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
