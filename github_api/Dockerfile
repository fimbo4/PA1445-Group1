FROM python:3.13-slim
WORKDIR /app
COPY ./database.py /app/
COPY ./main.py /app/
COPY ./requirements.txt /app/
RUN pip install -r requirements.txt
CMD ["python3", "main.py"]