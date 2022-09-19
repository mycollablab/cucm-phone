# cucm-phone

CUCMPhone lets you connect to a CUCM connect Cisco IP phone via the phone's web GUI and XML API and pull information as well as perform phone control functions like dialing numbers, pressing buttons and pull screenshots.


Generate a report from a list of phones with all data:
```
phoneList = ['172.20.130.254','172.20.130.253']
phones = []
for phone in phoneList:
	phones.append(Connect(phone))

for phone in phones:
	print(phone.details())
```

Control Device:
```
phone = Connect("172.20.130.254", username="bob", passwd="STRONG")
phone.press("settings")
phone.press("7")
phone.press("4")

phone.screenshot("./this_phone.png")
```

See switch neighbor:
```
print(phone.cdp_neighbor())
print(phone.lldp_neighbor())

```

Debug media:
```
phone.dial("+18004444444")
print(phone.media_stream(1))
```
