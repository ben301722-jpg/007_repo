import sys
sys.path.insert(0, '.')
from backend.parser import parse, PcapParser, _resolve_protocol, _detect_format

print('imports OK')
print(_resolve_protocol(6), _resolve_protocol(17), _resolve_protocol(1), _resolve_protocol(58), _resolve_protocol(9999))

# Test magic byte detection
try:
    _detect_format(b'garbage')
    print('ERROR: should have raised')
except ValueError as e:
    print('ValueError for garbage bytes: OK')

assert _detect_format(b'\xd4\xc3\xb2\xa1' + b'\x00'*100) == 'pcap'
print('pcap LE magic: OK')
assert _detect_format(b'\xa1\xb2\xc3\xd4' + b'\x00'*100) == 'pcap'
print('pcap BE magic: OK')
assert _detect_format(b'\x0a\x0d\x0d\x0a' + b'\x00'*100) == 'pcapng'
print('pcapng magic: OK')
print('All smoke tests passed.')
