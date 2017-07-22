# Ansible notes

This article gives a quick overview of the Ansible implementation included in the /samples directory.

## Overview / Base Assumptions

Docker files to build an ansible Docker container are included (cf samples/ansible-docker). This might help avoid some of the difficulties experienced with the various public Docker Hub Ansible containers.

The ansible scripts were coded for deployment to Windows Server 2012R2 and CentOS 7.

The Windows server is assumed to be attached to the Windows domain. There is a service acct which has access to the Windows server (to run the scripts) as well as Read-Only access to the production SCCM database.

On Linux, the code runs in a Docker container. The Ansible Linux script installs docker-compose on the target production host and builds the container there. This was thought to be simpler than trying to copy containers or other similar approaches.

The scripts are in samples/ansible.

The following gives openstack / ansible commands that could be used to deploy new Windows + Linux servers.

Throughout the samples, site-dependent values to be modified are indicated by "<" / ">". e.g.
_<my_key.pem>_

##  Create a new linux instance

```bash
openstack server create --image centos-7 --security-group <my_grp> \
--key-name <my_key> --wait --max 1 --min 1 --flavor <my_image>  my_new_linux
```

Manually update hosts file with new IP

### Test that environment is working

```bash
ansible all -m ping -l sccmlinux --vault-password-file \
<my_ansible_vault_pwd_file>
```

### Configure linux

```bash
ansible-playbook -v site.yml -l sccmlinux --vault-password-file \
<my_ansible_vault_pwd_file>
```

Transfer the floating IP to the new machine
Do a manual transfer of the sccm files from the windows
Do a test run on the new Linux.

```bash
openstack server remove floating ip <server_id> <ip-address>
openstack server add floating ip <server_id> <ip-address>
```


## Create a new Windows instance

### Get the windows local admin password

Next get the Windows Admin pwd and update the Ansible vault file with the new password:

```bash
openstack server list
nova get-password my_instance-s_ID startup/<my_key.pem>

ansible-vault edit -v --vault-password-file \
<my_ansible_vault_pwd_file> group_vars/sccmwin/vault.yml

# -e "ansible_user=Admin ansible_password=mypass"
```


### Update the Ansible hosts file

Configure the host IP address in the inventory hosts file.

### Test that environment is working

Check the syntax of site.yml, then ping the new host.

```bash
ansible-playbook --syntax-check site.yml --vault-password-file \
<my_ansible_vault_pwd_file>

ansible sccmwin -m win_ping -vvv --vault-password-file \
<my_ansible_vault_pwd_file>
```

Then (_take your courage in both hands(!)_ and) run the full ansible script.


```bash
ansible-playbook -v site.yml -l sccmwin --vault-password-file \
<my_ansible_vault_pwd_file>
```

## Test the deployment

### Logon with RDP again to run script manually from the Windows host

Move the floating IP to point to the new linux host.

```bash
openstack server remove floating ip <server_id> <ip-address>
openstack server add floating ip <server_id> <ip-address>
```

Now login to the new Windows host using the service account. This will ensure that the credentials are correct for the requests.

Execute the started task once manually on the Windows machine using the Task Scheduler to ensure that scheduled task is working correctly.

This should extract the SCCM data and (optionally) AD data. Data will be transferred from the Windows host to the Linux host.

### Check that the Linux host is working correctly.

Log on to the Linux host.

```bash
ssh -i <my_ssh_key.pem> \
-o StrictHostKeyChecking=no <my_user>@<my_floating_IP>
```

Take down the container and fire up a command line. Run the vulnmine code manually.


```bash
cd /var/deploy/dockerbuild
docker-compose down -v

docker-compose run pyprod bash

python src/vulnmine.py -a 'all'
```

Exit the container, and check the files in the /var/deploy/csv directory.
Bring up the production container which will loop forever in the python mainline. Vulnmine will be scheduled to run once a day.

```bash
docker-compose down -v
docker-compose up -d
```


## Troubleshooting in production

On CentOS, journalctl has the Docker O/P.
To troubleshoot, the production container can be taken down temporarily as documented above. The following could be run in bash cmdline:


```python
import pandas as pd
import numpy as np

import os
import sys

mydf = pd.read_pickle( )
```

To delete previous work and force a rebuild of the container:

```bash
docker-compose down –v
docker-compose build
```


