import os

print("upgrading pip...")
os.system('cmd /c python -m pip install --upgrade pip')

print("updated pip, now installing packages.")
os.system('cmd /c pip install -r requirements.txt')


print()
print("you are almost ready to go")
print("you just need to enable python throw the firewall")