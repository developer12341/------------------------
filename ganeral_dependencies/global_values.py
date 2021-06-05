IP, PORT = "127.0.0.1", 12345

# setting some contents
LOGIN = b'\x01'
REGISTER = b'\x02'
SEND_MSG = b'\x03'
SEND_FILE = b'\x04'
SEND_IMG = b'\x05'
ADD_CHAT = b'\x06'
GET_GROUP_INFO = b'\x07'
JOIN_CHAT = b'\x08'
GET_USERS = b'\x09'
CLOSE_CONN = b'\x0a'
LEAVE_CHAT = b'\x0b'
REG_LOGIN_SUC = b'\x0c'
REG_LOGIN_FAIL = b'\x0d'
GET_GROUP_KEY = b'\x0e'
FORGOT_MY_PASSWORD = b'\x0f'
AUTHENTICATE_EMAIL = b'\x10'
USERNAME_TAKEN = b'\x11'
EMAIL_TAKEN = b'\x12'
EMAIL_DOESNT_EXIST = b'\x13'
SEND_PIN_CODE = b'\x14'
CLIENT_KEYS = b'\x15'
USERNAME_DOESNT_EXIST = b'\x16'
RESET_PASSWORD = b'\x17'
GET_CHATS = b'\x18'
CREATE_CHAT = b'\x19'
CANT_JOIN_CHAT = b'\x1a'
END_SESSION = b'\x1b'
SEND_GROUP_KEYS = b'\x1c'
JOIN_PASSWORD_LESS_CHAT = b'\x1d'
USER_LOGGED_IN = b'\x1e'
CREATE_PUBLIC_CHAT = b'\x1f'

# flags - to check packet validity and to let the receiver know for sure what this packet is
CONTENT_PACKET = b'\x01'
FILE_NAME_PACKET = b'\x02'
USERNAME_PACKET = b'\x03'
SOMETHING_ELSE = b'\x04'

HEADER_SIZE = 16  # bytes
PACKET_SIZE = 1024  # bytes
CONTENT_SIZE = PACKET_SIZE - HEADER_SIZE
IMG_SIZE_FAC = 0.5  # 0 < IMG_SIZE_FAC < 1

PASSWORD_MIN_LEN = 5
PASSWORD_MAX_LEN = 100
USERNAME_MIN_LEN = 5
USERNAME_MAX_LEN = 30

image_file_formats = ["BMP", "EPS", "GIF", "ICNS", "ICO", "IM", "JPEG", "JPEG 2000", "MSP", "PCX", "PNG", "PPM", "SGI",
                      "TGA", "TIFF"]


kaomoji_folder_list = ['anger', 'apologizing', 'bear', 'bird', 'cat', 'confusion', 'dissatisfaction', 'dog', 'doubt',
                       'embarrassment', 'enemies', 'faces', 'fear', 'fish', 'food', 'friends', 'games', 'greeting',
                       'hiding', 'hugging', 'indifference', 'joy', 'love', 'magic', 'music', 'nosebleeding', 'pain',
                       'pig', 'rabbit', 'running', 'sadness', 'sleeping', 'spider', 'surprise', 'sympathy', 'weapons',
                       'winking', 'writing']
