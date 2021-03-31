import smtplib, ssl, random
def send_authentication_email(receiver_email):
    try:
        port = 587  # For starttls
        smtp_server = "smtp.gmail.com"
        sender_email = "sendme854@gmail.com"
        password = "sending123"
        uniqe_id = str(random.randrange(99999,999999))
        message = """Subject: sendme authentication

Welcome to sendme!
We hope you will have a grate time in our app
the authentication code is: {}""".format(uniqe_id)

        context = ssl.create_default_context()
        server =  smtplib.SMTP(smtp_server, port)
        server.ehlo() 
        server.starttls(context=context)
        server.ehlo() 
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, message)
        return uniqe_id
    except:
        return False
if __name__ == "__main__":
    uniqe_id = send_authentication_email("idodon33@gmail.com")
    #print(uniqe_id)