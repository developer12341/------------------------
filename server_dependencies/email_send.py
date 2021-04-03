import random
import smtplib
import ssl


def send_authentication_email(receiver_email):
    try:
        port = 587  # For starttls
        smtp_server = "smtp.gmail.com"
        sender_email = "sendme854@gmail.com"
        password = "sending123"
        unique_id = str(random.randrange(99999, 999999))
        message = """Subject: sendme authentication
    
Welcome to sendme!
We hope you will have a grate time in our app
the authentication code is: {}""".format(unique_id)

        context = ssl.create_default_context()
        server = smtplib.SMTP(smtp_server, port)
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, message)
        return unique_id
    except smtplib.SMTPRecipientsRefused:
        return False


if __name__ == "__main__":
    id_test = send_authentication_email("idodon33")
    print(id_test)
