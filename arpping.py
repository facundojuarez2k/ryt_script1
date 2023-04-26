import sys
import argparse
import re
#from scapy import Scapy


def main():
    try:
        args = parse_args()
        validate_args(args)
    except ValueError as ex1:
        print(f'ERROR: {str(ex1)}', file=sys.stderr)
    return 0


def parse_args():
    '''
    Captura y retorna los argumentos del programa
    '''
    parser = argparse.ArgumentParser(description='ARP Ping')
    parser.add_argument(dest='ip_address', type=str,
                        help='Dirección IPv4 a consultar')
    parser.add_argument('--count', '-c', dest='count', type=int,
                        help='Cantidad de mensajes ARP who-has. Admite valores enteros mayores o iguales a 0. El valor 0 equivale a una cantidad infinita. (Default = 0) (Opcional)', default=0)
    parser.add_argument('--device', '-d', dest='device', type=int,
                        help='Interfaz de red a utilizar (Requerido)', required=True)
    return parser.parse_args()


def validate_args(args: object):
    '''
    Valida los argumentos del programa
    '''
    if not hasattr(args, 'count') or args.count < 0:
        raise ValueError(
            'El argumento count debe ser un entero mayor o igual a cero')


def is_valid_ipv4(address: str) -> bool:
    '''
    Retorna True si la cadena de caracteres address es una dirección IPv4 válida en formato dot-decimal (190.30.2.5)
    '''
    ipv4_address_format = re.compile(
        r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
    match = re.fullmatch(ipv4_address_format, address)
    return match is not None


if __name__ == '__main__':
    main()
