#!/usr/bin/env python
import time
from pymodbus.client import ModbusUdpClient

with ModbusUdpClient('127.0.0.1', port=1502) as client:
    
    input()

    # Create an array of boolean values to write to the coils
    values = [True] * 32

    # Write the values to the coils starting at address 5
    client.write_coils(1, values)

    values = [False] * 32

    # Write the values to the coils starting at address 5
    client.write_coils(1, values)

    # other write
    for addr in range(200, 200 + 3*48):
        client.write_coil(addr, False)
        # time.sleep(0.1)
        client.write_coil(addr, True)
