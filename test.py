import os
import subprocess

FILE_BROWSER_PATH = os.path.join(os.getenv('WINDIR'), 'explorer.exe')


def explore(path):
    # explorer would choke on forward slashes
    path = os.path.normpath(path)

    if os.path.isdir(path):
        subprocess.run([FILE_BROWSER_PATH, path])
    elif os.path.isfile(path):
        subprocess.run([FILE_BROWSER_PATH, '/select,', os.path.normpath(path)])


explore("C:\\Users\\idodo\\Desktop\\ido_don_sendme_20-21\\files\\sample_img.jpeg")
