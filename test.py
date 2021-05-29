import datetime
import ntpath
import os
import time

# txt_file = open(".\\code_txt_file.txt", "r")
# content = txt_file.read()
# content = content.strip("\n")
# content = content.split("*")
# for item in content:
#     if not item:
#         content.remove(item)
#     if len(item) < 10:
#         content.remove(item)
# file_name = []
# for item in range(len(content)):
#     content[item] = content[item].strip("\n")
#     print(content[item][14:content[item].find("\n")])
#     print()
#     file_name.append(content[item][14:content[item].find("\n")])
# print(file_name)
# descriptions = dict(zip(file_name,content))
# print(descriptions)
def extract_file_name(path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)
#

def walk_through_files(path, file_extension='.html'):
    for (dirpath, dirnames, filenames) in os.walk(path):
        for filename in filenames:
            if filename.endswith(file_extension):
                yield os.path.join(dirpath, filename)

#
# txt_file = open(".\\code_txt_file.txt", "w")
# for path in walk_through_files(os.getcwd(), ".py"):
#     if extract_file_name(path) == "test.py":
#         pass
#     if extract_file_name(path) in file_name:
#         with open(path, "r") as f:
#             content = "\n\n\n\n"
#             for i in range(2):
#                 content += "*" * 70
#                 content += "\n"
#
#             content += descriptions[extract_file_name(path)]
#             content += "\n\n"
#             for i in range(2):
#                 content += "*" * 70
#                 content += "\n"
#             content += "\n\n\n\n"
#             content += f.read()
#             txt_file.write(content)
class_diagram = """RequestHandler\fn\n\f_________________________________\n\f08addr\n\f08auth_for_change_password : bool\n\f08chat_id : NoneType\n\f08chat_id_cli\n\f08chat_id_name\n\f08chat_name : NoneType\n\f08chat_name_chat_id\n\f08client\n\f08current_details : list\n\f08db_obj\n\f08id_check : NoneType\n\f08keep_running : bool\n\f08key : bytes\n\f08password : str\n\f08public_chat_key\n\f08queue_requests : list\n\f08server_values\n\f08user_list\n\f08username : NoneType\n\f_________________________________\n\f10authenticate_email()\n\f10broadcast_packets()\n\f10close_conn()\n\f10create_chat()\n\f10create_public_chat()\n\f10decrypt()\n\f10get_chats()\n\f10get_group_info()\n\f10get_users()\n\f10join_chat()\n\f10join_password_less_chat()\n\f10leave_chat()\n\f10login()\n\f10register()\n\f10reset_password()\n\f10run()\n\f10send_group_keys()

"""
print(class_diagram)
class_diagram.replace("\f","")
