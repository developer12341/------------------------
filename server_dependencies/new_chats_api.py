import socket
import threading
from typing import Optional


class Protocol(threading.Thread):
    def __init__(self):
        # [(chat_name, is_password_protected, creating client)]
        self.queue = []
        self.chat_list = []
        self.keep_running = True
        self.user_list = set()
        threading.Thread.__init__(self)

    def run(self) -> None:
        while self.keep_running:
            for (chat_name, is_password_protected, creating_client) in self.queue:
                content = {"chat_name": chat_name, "is_password_protected":str(is_password_protected)}
                for client in self.user_list:
                    if client is not creating_client:
                        pass

            self.queue.clear()

    def remove_user(self, user:socket.socket):
        self.user_list.remove(user)

    def join(self, timeout: Optional[float] = ...) -> None:
        self.run = False

    def add_user(self, user:socket.socket):
        self.user_list.add(user)