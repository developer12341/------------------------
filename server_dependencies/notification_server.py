import socket,threading
from ganeral_dependencies import protocols
from ganeral_dependencies.global_values import *

def main():
    #setting up the notification_port
    notification_server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    notification_server.bind((IP,NOTIFICATION_PORT))
    notification_server.listen()
    while True:
        client, addr = server.accept()
        username = client.recv(PACKET_SIZE)
        if