FROM pypy:3-6
ENV LOGLEVEL=info

COPY requirements.txt requirements.txt
RUN pip install -f requirements.txt

COPY controller.py /controller.py

EXPOSE 5000

CMD gunicorn -w 4 --forwarded-allow-ips "*" controller:app -b :5000 --log-file - --log-level ${LOGLEVEL}
