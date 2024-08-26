Katkıda Bulunma Rehberi
Web Güvenlik Tarayıcısı projesine katkıda bulunmak istediğiniz için teşekkür ederiz! Bu rehber, projeye nasıl yeni özellikler ekleyebileceğinizi ve mevcut özellikleri nasıl geliştirebileceğinizi açıklamaktadır.
İçindekiler

Geliştirme Ortamının Kurulumu
Yeni Özellik Ekleme Süreci
Kod Stili ve Standartları
Test Etme
Pull Request Gönderme

Geliştirme Ortamının Kurulumu

Projeyi forklayın ve yerel makinenize klonlayın:
Copygit clone https://github.com/kerimaksanaoglu/web-guvenlik-tarayicisi.git

Proje dizinine gidin:
Copycd web-guvenlik-tarayicisi

Sanal bir Python ortamı oluşturun ve etkinleştirin:
Copypython -m venv venv
source venv/bin/activate  # Windows için: venv\Scripts\activate

Gerekli bağımlılıkları yükleyin:
Copypip install -r requirements.txt


Yeni Özellik Ekleme Süreci

Yeni bir dal (branch) oluşturun:
Copygit checkout -b ozellik/yeni-ozellik-adi

web_security_scanner.py dosyasını açın ve TarayiciMotoru sınıfına yeni metodu ekleyin. Örneğin, yeni bir güvenlik kontrolü eklemek için:
pythonCopyasync def yeni_guvenlik_kontrolu(self, url):
    try:
        async with self.session.get(url) as yanit:
            icerik = await yanit.text()
            # Yeni güvenlik kontrolü mantığı burada
            if "güvenlik açığı belirtisi" in icerik:
                aciklama = (
                    "Yeni güvenlik açığı tespit edildi. "
                    f"Etkilenen URL: {url}\n"
                    "Açıklama: ..."
                )
                self.guvenlik_aciklari.append({
                    "tip": "Yeni Güvenlik Açığı",
                    "url": url,
                    "aciklama": aciklama
                })
                self.logSinyali.emit(f"Yeni güvenlik açığı bulundu: {url}")
    except Exception as e:
        self.logSinyali.emit(f"Hata oluştu: {str(e)}")

Yeni metodu tarama_yap metoduna ekleyin:
pythonCopyasync def tarama_yap(self):
    self.session = aiohttp.ClientSession()
    taranacaklar = [self.hedef_url]
    while taranacaklar:
        gorevler = [self.tara(url) for url in taranacaklar[:self.is_parcacigi]]
        yeni_urller = await asyncio.gather(*gorevler)
        taranacaklar = taranacaklar[self.is_parcacigi:]
        for urls in yeni_urller:
            if urls:
                taranacaklar.extend(urls)
        
        # Yeni güvenlik kontrolünü ekleyin
        await self.yeni_guvenlik_kontrolu(url)
    
    await self.session.close()

Eğer yeni özellik kullanıcı arayüzünde değişiklik gerektiriyorsa, WebGuvenlikTarayicisi sınıfını güncelleyin. Örneğin, yeni bir sekme eklemek için:
pythonCopydef arayuz_olustur(self):
    # ... mevcut kod ...
    
    self.yeni_ozellik_sekmesi = QWidget()
    self.yeni_ozellik_duzen = QVBoxLayout(self.yeni_ozellik_sekmesi)
    self.yeni_ozellik_sonuc = QTextEdit()
    self.yeni_ozellik_duzen.addWidget(self.yeni_ozellik_sonuc)
    
    self.sekme_widget.addTab(self.yeni_ozellik_sekmesi, "Yeni Özellik")
    
    # ... mevcut kod ...

Yeni özelliğin sonuçlarını göstermek için sonuclari_goster metodunu güncelleyin:
pythonCopydef sonuclari_goster(self, sonuclar):
    # ... mevcut kod ...
    
    for sonuc in sonuclar:
        if sonuc['tip'] == "Yeni Güvenlik Açığı":
            self.yeni_ozellik_sonuc.append(f"URL: {sonuc['url']}\nAçıklama: {sonuc['aciklama']}\n\n")
    
    # ... mevcut kod ...


Kod Stili ve Standartları

PEP 8 kurallarına uyun.
Anlamlı değişken ve fonksiyon isimleri kullanın.
Karmaşık kod bloklarını açıklayan yorumlar ekleyin.
Türkçe karakter kullanmaktan kaçının (ı, ğ, ü, ş, ö, ç).

Test Etme

Yeni özelliğiniz için birim testleri yazın. tests/ dizininde yeni bir test dosyası oluşturun:
pythonCopy# tests/test_yeni_ozellik.py
import unittest
from web_security_scanner import TarayiciMotoru

class TestYeniOzellik(unittest.TestCase):
    def test_yeni_guvenlik_kontrolu(self):
        # Test kodunuzu buraya yazın
        pass

Tüm testleri çalıştırın:
Copypython -m unittest discover tests


Pull Request Gönderme

Değişikliklerinizi commit edin:
Copygit add .
git commit -m "Yeni özellik: [ÖZELLİK ADI]"

Değişikliklerinizi GitHub'daki forkunuza push edin:
Copygit push origin ozellik/yeni-ozellik-adi

GitHub'da yeni bir Pull Request oluşturun.
Pull Request açıklamasında, eklediğiniz özelliği detaylı bir şekilde açıklayın ve varsa ekran görüntüleri ekleyin.

Katkınız için tekrar teşekkür ederiz! Herhangi bir sorunuz olursa, lütfen bir Issue açmaktan çekinmeyin.
