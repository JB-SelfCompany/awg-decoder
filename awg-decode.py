import sys
import struct
import zlib
import base64
import argparse
import socket
import ipaddress
import re

def qCompress(data, level=-1):
    compressed = zlib.compress(data, level)
    header = struct.pack('>I', len(data))
    return header + compressed

def qUncompress(data):
    if len(data) < 4:
        return b''
    uncompressed_size = struct.unpack('>I', data[:4])[0]
    compressed_data = data[4:]
    try:
        uncompressed_data = zlib.decompress(compressed_data)
    except zlib.error:
        return b''
    if len(uncompressed_data) != uncompressed_size:
        return b''
    return uncompressed_data

def base64url_encode(data):
    encoded = base64.urlsafe_b64encode(data)
    return encoded.rstrip(b'=')

def base64url_decode(data):
    padding_needed = (4 - len(data) % 4) % 4
    data += b'=' * padding_needed
    return base64.urlsafe_b64decode(data)

def is_ip_address(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def resolve_dns_to_ip(dns_name):
    try:
        ip_address = socket.gethostbyname(dns_name)
        return ip_address
    except socket.gaierror:
        return None

def process_conf_data(data):
    def replace_endpoint(match):
        full_line = match.group(0)
        prefix = match.group(1)
        address = match.group(2)
        port = match.group(3)
        suffix = match.group(4)
        if not is_ip_address(address):
            resolved_ip = resolve_dns_to_ip(address)
            if resolved_ip:
                print(f"Resolved DNS '{address}' to IP '{resolved_ip}'", file=sys.stderr)
                return f"{prefix}{resolved_ip}:{port}{suffix}"
            else:
                print(f"Error: Could not resolve DNS name '{address}'", file=sys.stderr)
                sys.exit(1)
        else:
            return full_line
    pattern = r'^(.*Endpoint\s*=\s*)([^\s:]+)(?::(\d+))(.*)$'
    return re.sub(pattern, replace_endpoint, data, flags=re.MULTILINE)

def encode(data):
    data_bytes = data.encode('utf-8')
    compressed = qCompress(data_bytes, level=8)
    base64_encoded = base64url_encode(compressed)
    s = 'vpn://' + base64_encoded.decode('ascii')
    return s

def decode(s):
    data = s.replace('vpn://', '')
    data_bytes = data.encode('ascii')
    compressed = base64url_decode(data_bytes)
    uncompressed = qUncompress(compressed)
    if uncompressed:
        result = uncompressed
    else:
        result = compressed
    return result.decode('utf-8')

def main():
    parser = argparse.ArgumentParser(description='Encode and decode VPN configuration files to/from vpn:// format.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', '--encode', action='store_true', help='Encode a .conf file to vpn:// format.')
    group.add_argument('-d', '--decode', action='store_true', help='Decode a vpn:// string to configuration data.')
    parser.add_argument('input', help='Input file for encoding or vpn:// string for decoding.')
    parser.add_argument('-o', '--output', help='Output file. If not specified, output will be printed to console.')

    args = parser.parse_args()

    if args.encode:
        try:
            with open(args.input, 'r', encoding='utf-8') as f:
                data = f.read()
        except FileNotFoundError:
            print(f'Error: File {args.input} not found.')
            sys.exit(1)
        except Exception as e:
            print(f'Error reading file {args.input}: {e}')
            sys.exit(1)

        processed_data = process_conf_data(data)

        encoded_string = encode(processed_data)

        if args.output:
            try:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(encoded_string)
                print(f'Encoded vpn:// string written to {args.output}')
            except Exception as e:
                print(f'Error writing to file {args.output}: {e}')
        else:
            print(encoded_string)

    elif args.decode:
        vpn_string = args.input

        decoded_data = decode(vpn_string)

        if args.output:
            try:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(decoded_data)
                print(f'Decoded configuration data written to {args.output}')
            except Exception as e:
                print(f'Error writing to file {args.output}: {e}')
        else:
            print(decoded_data)

if __name__ == '__main__':
    main()
