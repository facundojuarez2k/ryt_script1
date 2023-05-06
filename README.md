# ARP Ping

## Requisitos

-   Python 3.6+
-   Scapy: `apt install python3-scapy`

## Ejecución

`sudo python3 arping.py 172.16.5.30 -d eth0`

## Uso

```
usage: arping.py [-h] [--count COUNT] --device DEVICE target_ip_address

ARP Ping

positional arguments:
  target_ip_address     Destination IP Address

options:
  -h, --help            show this help message and exit
  --count COUNT, -c COUNT
                        Amount of who-has messages to send. Allows integer values greater than or equal to 0. Setting this flag to 0 implies sending
                        packets indefinitely. (Default = 0) (Optional)
  --device DEVICE, -d DEVICE
                        Network interface to use (Required)
```

## Ejemplos

#### Enviar 3 paquetes ARP request a la dirección IP 192.168.50.3 a través de la interfaz enp0s3

`sudo python3 arping.py 192.168.50.3 -d enp0s3 -c 3`

#### Enviar paquetes ARP request indefinidamente a la dirección IP 192.168.50.3 a través de la interfaz enp0s3

`sudo python3 arping.py 192.168.50.3 -d enp0s3`

ó

`sudo python3 arping.py 192.168.50.3 -d enp0s3 -c 0`
