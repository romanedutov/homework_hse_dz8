from scapy.all import *

pkts = rdpcap("xss_traffic.pcap")
print(f"📦 Всего пакетов: {len(pkts)}")
print("="*50)

for i, p in enumerate(pkts):
    if p.haslayer(Raw):
        try:
            data = p[Raw].load.decode('utf-8', errors='ignore')
            if "452952831240547056084599575978071731672" in data:
                print(f"\n🎯 НАЙДЕН ПАКЕТ #{i} С ТВОИМ XSS:")
                print("-"*40)
                
                # Разделяем на строки для читаемости
                lines = data.split('\r\n')
                
                # Показываем только важное
                for line in lines:
                    if line.startswith('GET') or 'Host:' in line or 'User-Agent:' in line:
                        print(line[:100])
                    elif '<script>' in line or 'alert' in line:
                        print(f"⚠️ XSS PAYLOAD: {line}")
                
                print("-"*40)
                print(f"📏 Длина данных: {len(data)} символов")
                break
                
        except:
            continue

print("\n✅ Анализ завершен!")
