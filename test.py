import json

d = {1:2, 3:True}

s = json.dumps(d)
print(d)
print(s)
print(type(s))
dd = json.loads(s)
print(dd)