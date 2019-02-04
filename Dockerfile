FROM pypy:3-6
ENV LOGLEVEL=info

COPY requirements.txt requirements.txt
RUN mkdir tenant-manager && pip install gunicorn && pip install -r requirements.txt

WORKDIR /tenant-manager
COPY lib/*.py /tenant-manager/lib/
COPY controller.py settings.py /tenant-manager/

EXPOSE 5000

CMD gunicorn -w 4 --forwarded-allow-ips "*" controller:app -b :5000 --log-file - --log-level ${LOGLEVEL}
