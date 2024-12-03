from flask import Flask
from apscheduler.schedulers.background import BackgroundScheduler
import boto3
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

### add for test on local
from dotenv import find_dotenv, load_dotenv
dotenv_path = find_dotenv()
load_dotenv(dotenv_path)
####

app = Flask(__name__)

# initialize DynamoDB client
dynamodb = boto3.resource('dynamodb', region_name='us-west-2')
table = dynamodb.Table('subscription')


def send_email(to_address, subject, body):
    msg = MIMEMultipart()
    username = os.getenv('MAIL_USERNAME')
    msg['From'] = username
    msg['To'] = to_address
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'html'))

    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls()
        server.login(username, os.getenv('MAIL_PASSWORD'))
        server.sendmail(username, to_address, msg.as_string())


def fetch_data_and_send_emails():
    response = table.scan()
    items = response['Items']
    for item in items:
        email = item.get('email')
        if email:
            subject = ""
            body = ""
            send_email(email, subject, body)


scheduler = BackgroundScheduler()
scheduler.add_job(func=fetch_data_and_send_emails, trigger="interval", hours=1)
scheduler.start()


@app.route('/')
def home():
    return "Email scheduler is running!"


if __name__ == '__main__':
    send_email('ggzeng@gmail.com', 'Test from Intelligence', 'Welcom')
