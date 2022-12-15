#!/usr/bin/env python
import time
from pymodbus.client import ModbusUdpClient

with ModbusUdpClient('127.0.0.1', port=502) as client:
    
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


# from pymodbus.client.sync import ModbusUdpClient
# from pymodbus.constants import Endian
# from pymodbus.payload import BinaryPayloadDecoder

# # Create a new Modbus client
# client = ModbusUdpClient("192.168.1.1", port=502)

# # Read the values of holding registers from the server
# response = client.read_holding_registers(0, 64, unit=1)
# if response.isError():
#     print("Failed to read holding registers:", response)
# else:
#     # Decode the register values
#     decoder = BinaryPayloadDecoder.fromRegisters(response.registers, byteorder=Endian.Big)

#     # Print the register values
#     for i in range(64):
#         print("Holding register %d: %d" % (i, decoder.decode_16bit_uint()))

# # Close the client connection
# client.close()
