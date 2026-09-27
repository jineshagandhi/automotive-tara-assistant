# High-Level Design: Connected Compact SUV, E/E architecture (excerpt)

Document status: fictional sample for demonstration. Revision B.

## 1. System overview

The vehicle uses a central gateway (CGW) that separates the Automotive Ethernet
backbone from the CAN-FD domain networks. The telematics control unit (TCU) and
the infotainment head unit (IVI) are connected to the Ethernet backbone together
with the central gateway.

## 2. Connectivity

The TCU provides 4G LTE connectivity to the OEM cloud back-end, receives
over-the-air (OTA) software updates for all ECUs and hosts the GNSS receiver used
for eCall. Customers use a companion mobile app to lock the vehicle remotely and
to pre-condition the cabin.

The infotainment head unit offers a Wi-Fi hotspot, Bluetooth hands-free calling
and a USB media port.

## 3. Chassis domain

The brake control unit (ESC) and the electric power steering (EPS) are connected
to the chassis CAN-FD network together with the central gateway. The ADAS
controller for adaptive cruise control is also on the chassis CAN-FD network.

## 4. Powertrain domain

The vehicle control unit (VCU), the battery management system (BMS) and the
on-board charger (OBC) share the powertrain CAN-FD network with the gateway. The
OBC implements ISO 15118 communication with the charging station through the
CCS charging inlet.

## 5. Body domain

The body control module (BCM) and the digital key module share the body CAN
network with the gateway. The digital key module supports phone as a key over
Bluetooth Low Energy and a key fob. The BCM receives TPMS tyre pressure sensors.

## 6. Diagnostics

The OBD-II diagnostic port is connected to the central gateway, which routes UDS
diagnostic requests to the domain ECUs.
