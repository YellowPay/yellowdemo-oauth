FROM python:2.7
MAINTAINER James Piechota <james@yellowpay.co>
EXPOSE 8001

RUN mkdir -p /app
WORKDIR /app
COPY . /app/
RUN pip install -r /app/requirements.txt
 
CMD [ "python", "manage.py", "runserver", "0.0.0.0:8001" ]
