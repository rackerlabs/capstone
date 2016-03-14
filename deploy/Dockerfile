# capstone
#
# VERSION               0.1

FROM capstone:base

EXPOSE 5000 35357

CMD sed -i "s/username =.*/username = $USERNAME/g" /etc/capstone/capstone.conf && \
    sed -i "s/password =.*/password = $PASSWORD/g" /etc/capstone/capstone.conf && \
    sed -i "s/base_url =.*/base_url = $BASE_URL/g" /etc/capstone/capstone.conf && \
    service apache2 start && \
    tail -F /var/log/keystone/*
