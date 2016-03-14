# capstone
#
# VERSION               0.1

FROM capstone:base

RUN apt-get install -y gettext-base

EXPOSE 5000 35357

ENV USER root

WORKDIR /pipeline/source

CMD envsubst < inventory_docker > inventory && \
    ansible-playbook -i inventory deploy.yml --tags config && \
    service apache2 start && \
    tail -F /var/log/keystone/*
