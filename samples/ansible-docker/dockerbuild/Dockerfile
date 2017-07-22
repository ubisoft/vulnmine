FROM ubuntu:latest

MAINTAINER lgordon *at* lgsec *dot* biz

ENV SHELL=/bin/bash NM_USR=ansible NB_UID=1000 NM_GRP=srm_sccm NB_GRP=1001

# Run as non-root user but allow full sudo without passwd
# Create ansible user with UID=1000, Group=1001

RUN groupadd -g $NB_GRP $NM_GRP  && \
	useradd -m -s $SHELL -u $NB_UID -g $NM_GRP $NM_USR


ENV HOME /home/$NM_USR


ARG DEBIAN_FRONTEND=noninteractive


RUN	apt-get -y update && \
	apt-get install -y \
			apt-utils \
			software-properties-common \
			&& \
	apt-add-repository -y ppa:ansible/ansible && \
	apt-get install -y \
			openssh-client \
			sudo less nano \
			rsync \
			python-pip \
			build-essential libssl-dev libffi-dev python-dev \
			locales \
			&& \

	# following will require specifying default realm

	apt-get install -y \
			libkrb5-dev \
			krb5-user \
			&& \
    apt-get purge -y --auto-remove && \
    apt-get clean


RUN pip install --no-cache-dir --proxy=$HTTP_PROXY --upgrade \
		pip \
		boto \
		cs \
		PyYAML \
		docker-py \
		"pywinrm>=0.1.1" \
		kerberos \
		requests_kerberos \
		cryptography \
		shade \
		ansible \
		python-openstackclient \
		python-novaclient \
		python-heatclient \
		os_client_config

#	Other config
#	Dynamic inventory files *have* to be in a location where ansible will look. e.g. /usr/local/bin will not work.

ADD "https://raw.githubusercontent.com/ansible/ansible/devel/examples/ansible.cfg" "/etc/ansible/"

ADD "https://raw.githubusercontent.com/ansible/ansible/devel/contrib/inventory/ec2.py" "/etc/ansible/"

ADD "https://raw.githubusercontent.com/ansible/ansible/devel/contrib/inventory/ec2.ini" "/etc/ansible/"

ADD "https://raw.githubusercontent.com/ansible/ansible/devel/contrib/inventory/openstack.py" "/etc/ansible/"

RUN	chmod 755 /etc/ansible/*py && \
	chmod 644 /etc/ansible/ec2.ini \
		/etc/ansible/ansible.cfg && \
	/bin/echo -e "[local]\nlocalhost ansible_connection=local" >> /etc/ansible/hosts && \
	locale-gen en_US.UTF-8 && \
	echo "ansible ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/ansible

USER $NM_USR

# Start up in the work directory
WORKDIR /home/$NM_USR/work

# No use trying to execute an interactive shell with docker-compose up
# CMD ["/bin/bash"]