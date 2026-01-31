from scapy.all import *

packets = []

def catch(pkt):
    packets.append(pkt)
    if pkt.haslayer(Raw):
        try:
            data = pkt[Raw].load.decode('utf-8', errors='ignore')
            if "452952831240547056084599575978071731672" in data:
                print("[+] Наш трафик!")
                # Показываем что нашли
                if "GET /" in data:
                    lines = data.split('\r\n')
                    print(f"   URL: {lines[0][:100]}")
        except:
            pass

print("[+] Ловлю трафик 20 сек...")
# МЕНЯЕМ порт с 443 на 80 для HTTP
sniff(filter="tcp port 80", prn=catch, timeout=20)
wrpcap("xss_traffic.pcap", packets)
print(f"[+] Сохранено {len(packets)} пакетов")
