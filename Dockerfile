FROM python:2.7.16-alpine3.9

MAINTAINER Lauris Vavere <lauris@ma-1.lv>

RUN apk add --no-cache make gcc python2-dev libffi-dev libc-dev openssl-dev krb5-libs krb5-dev

RUN pip install smbprotocol[kerberos] pypsexec pysmb

COPY resource.py /opt/resource/

RUN cd /opt/resource \
&& chmod +x resource.py \
&& ln -s resource.py check \
&& ln -s resource.py in \
&& ln -s resource.py out

WORKDIR /opt/resource/
