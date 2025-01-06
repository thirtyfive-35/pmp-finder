import requests
import json
import time

# API URL'ini belirtin (örnek URL'yi kullanarak)
url = "https://www.virustotal.com/api/v3/domains/23andme.com/subdomains?limit=500"

# API anahtarınızı burada belirtin
headers = {
    "x-apikey": "377d23724c7aa8beee2fd9fdee1b1c34ca07377052d5c4262d676b92b2ebf1b6"  # Buraya kendi API anahtarınızı ekleyin
}

# Subdomain'leri depolamak için bir liste
all_subdomains = []

# İlk isteği gönder
while url:
    # İstek at
    response = requests.get(url, headers=headers)
    
    # Yanıtı kontrol et (istek başarılı mı?)
    if response.status_code == 200:
        data = response.json()

        # Subdomain'leri çıkart
        for item in data['data']:
            all_subdomains.append(item['id'])

        # Eğer "next" linki varsa, bir sonraki sayfaya geç
        url = data['links'].get('next')
        
        # 15 saniye bekleyin, istek sınırını aşmamak için
        time.sleep(20)
    else:
        print(f"Hata: {response.status_code}")
        break

# Subdomain'leri bir .txt dosyasına kaydet
with open('subdomains.txt', 'w') as file:
    for subdomain in all_subdomains:
        file.write(subdomain + '\n')

print(f"Toplam {len(all_subdomains)} subdomain bulundu ve 'subdomains.txt' dosyasına kaydedildi.")
