# Install latest stable version of Docker python 2.x image from DockerHub.

FROM python:3-onbuild

# Configure environment
# 160719 cf Jupyter stack Dockerfile

ENV SHELL=/bin/bash NM_USR=jovyan NB_UID=1000 NM_GRP=jovyan NB_GRP=1000
ENV NM_GRPS=srm_sccm NB_GRPS=1001
ENV HOME /home/$NM_USR

# Create jovyan user with UID=1000, Group=1000
RUN groupadd -g $NB_GRP $NM_GRP  && \
	groupadd -g $NB_GRPS $NM_GRPS && \
	useradd -m -s $SHELL -u $NB_UID -g $NM_GRP -G $NM_GRPS $NM_USR

# Copy in contents of data/ and vulnmine/ directories for standalone container
COPY data/ /home/$NM_USR/work/data
COPY vulnmine/ /home/$NM_USR/work/vulnmine

# Set permissions
RUN chown -R $NM_USR:$NM_GRPS /home/$NM_USR/work/

# Run as non-root user
USER $NM_USR

# Start up in the work directory
WORKDIR /home/$NM_USR/work

CMD ["python", "vulnmine/__main__.py"]
