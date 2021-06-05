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


txt_file = open(".\\code_txt_file.txt", "w")
for path in walk_through_files(os.getcwd(), ".py"):
    if extract_file_name(path) == "test.py":
        pass
    if extract_file_name(path) in file_name:
        with open(path, "r") as f:
            content = "\n\n\n\n"
            for i in range(2):
                content += "*" * 70
                content += "\n"

            content += descriptions[extract_file_name(path)]
            content += "\n\n"
            for i in range(2):
                content += "*" * 70
                content += "\n"
            content += "\n\n\n\n"
            content += f.read()
            txt_file.write(content)