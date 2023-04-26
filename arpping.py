'''
ARP Ping script
'''
import sys
import argparse
import re
import time
import signal
import scapy.all as scapy
from scapy.layers.l2 import Ether, ARP


interrupted = False


def signal_handler(sig, frame):
    global interrupted
    interrupted = True


signal.signal(signal.SIGINT, signal_handler)


class PacketSender:
    def __init__(self, packet):
        self.packet = packet
        self.packets_sent = 0
        self.packets_received = 0

    def set_packet(self, packet):
        self.packet = packet

    def get_packet(self):
        return self.packet

    def print_summary(self):
        print(
            f'Sent {self.packets_sent} probes, Received {self.packets_received} responses')

    def send_packet(self):
        '''
        Envía el paquete utilizando la función srp1 de Scapy e imprime el resultado por consola
        '''
        ans = scapy.srp1(self.packet, verbose=False, timeout=5)
        self.packets_sent += 1

        if ans:
            self.packets_received += 1
            print(f'Reply from {ans[ARP].psrc} [{ans[ARP].hwsrc}]')
        else:
            print('Request timeout')


def main() -> any:
    '''
    Entrypoint
    '''
    try:
        args = parse_args()
        validate_args(args)

        # Definir parámetros del paquete ARP
        protocol_type = 0x0800  # IPv4
        operation = 1           # who-has
        src_hw_address = scapy.get_if_hwaddr(args.device)
        src_protocol_address = scapy.get_if_addr(args.device)
        dst_protocol_address = args.target_ip_address

        arp_packet = Ether()/ARP()

        # Construir paquete ARP
        arp_packet[ARP].ptype = protocol_type
        arp_packet[ARP].op = operation
        arp_packet[ARP].hwsrc = src_hw_address
        arp_packet[ARP].psrc = src_protocol_address
        arp_packet[ARP].pdst = dst_protocol_address

        # Armar trama Ethernet
        arp_packet[Ether].dst = "ff:ff:ff:ff:ff:ff"

        # Iniciar envío de paquetes
        sender = PacketSender(arp_packet)
        iterations = 0

        while True:
            if interrupted:
                break
            
            sender.send_packet()

            if args.count > 0:
                iterations += 1
                if args.count == iterations:
                    break

            time.sleep(1)

        sender.print_summary()

    except ValueError as ex1:
        print(f'ERROR: {str(ex1)}', file=sys.stderr)

    return 0


def parse_args() -> object:
    '''
    Captura y retorna los argumentos del programa
    '''
    parser = argparse.ArgumentParser(description='ARP Ping')
    parser.add_argument(dest='target_ip_address', type=str,
                        help='Dirección IPv4 a consultar')
    parser.add_argument('--count', '-c', dest='count', type=int,
                        help='Cantidad de mensajes ARP who-has. Admite valores enteros mayores o iguales a 0. El valor 0 equivale a una cantidad infinita. (Default = 0) (Opcional)', default=0)
    parser.add_argument('--device', '-d', dest='device', type=str,
                        help='Interfaz de red a utilizar (Requerido)', required=True)
    return parser.parse_args()


def validate_args(args: object) -> None:
    '''
    Valida los argumentos del programa
    '''
    if hasattr(args, 'count') is False or args.count < 0:
        raise ValueError(
            'El argumento count debe ser un entero mayor o igual a cero')
    if is_valid_ipv4(args.target_ip_address) is False:
        raise ValueError(
            f'Dirección {args.target_ip_address} no es una dirección IPv4 no válida')
    if is_valid_device(args.device) is False:
        raise ValueError(
            f'Interfaz {args.device} no encontrada')


def is_valid_ipv4(address: str) -> bool:
    '''
    Retorna True si la cadena de caracteres address es una dirección IPv4 válida en formato dot-decimal (190.30.2.5)
    '''
    ipv4_address_format = re.compile(
        r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
    match = re.fullmatch(ipv4_address_format, address)
    return match is not None


def is_valid_device(device: str) -> bool:
    '''
    Retorna True si la cadena de caracteres device corresponde a una interfaz de red válida del sistema
    '''
    return device in scapy.get_if_list()


if __name__ == '__main__':
    main()
