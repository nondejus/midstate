#!/bin/env python3

from midstate import midstate
from binascii import hexlify

data = \
		'01000000' + \
		'e4e89df8481bc576b99f665762cb8266f855c6684016b8b4d16976f200000000' + \
		'e1d14f0898e61d024f0e0172fc634669f5fcd56d4e01ca10e9377b056863d155' + \
		'c866204f' + \
		'f8ff071d' + \
		'00000000' + \
		'000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000'
target_midstate = \
		b'b8101f7c4a8e294ecbccb941dde17fd461dc39ff102bc37bb7ac7d5b95290166'

datab = bytes.fromhex(data);
print("target:")
print(target_midstate)
print("got:")
print(hexlify(midstate(datab)))
