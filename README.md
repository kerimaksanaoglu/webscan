# webscan
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GitHub Proje Yapısı ve Dosyaları</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2 {
            color: #2c3e50;
        }
        pre {
            background-color: #f4f4f4;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 10px;
            overflow-x: auto;
        }
        code {
            font-family: Consolas, Monaco, 'Andale Mono', monospace;
            background-color: #f4f4f4;
            padding: 2px 4px;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <h1>GitHub'a Yüklenecek Proje Dosyaları ve İçerikleri</h1>

    <h2>1. Ana Python dosyanız</h2>
    <p>Örneğin, <code>web_security_scanner.py</code></p>

    <h2>2. requirements.txt</h2>
    <p>Bu dosya, projenizin bağımlılıklarını listeler. İçeriği:</p>
    <pre><code>PyQt5==5.15.4
requests==2.26.0
beautifulsoup4==4.10.0
aiohttp==3.8.1</code></pre>

    <h2>3. README.md</h2>
    <p>Bu dosya, projenizi tanıtır ve nasıl kullanılacağını açıklar. Örnek içerik:</p>
    <pre><code># Web Güvenlik Tarayıcısı

Bu proje, web uygulamalarında güvenlik açıklarını taramak için geliştirilmiş bir Python uygulamasıdır. PyQt5 kullanılarak oluşturulan kullanıcı dostu bir arayüze sahiptir.

## Özellikler

- XSS, SQL Injection, CSRF gibi yaygın güvenlik açıklarını tarar
- Kullanıcı dostu grafiksel arayüz
- Detaylı tarama raporları
- Asenkron tarama işlemleri için yüksek performans

## Kurulum

1. Repoyu klonlayın:
   ```
   git clone https://github.com/kullaniciadi/web-guvenlik-tarayicisi.git
   ```

2. Gerekli bağımlılıkları yükleyin:
   ```
   pip install -r requirements.txt
   ```

## Kullanım

1. Programı çalıştırın:
   ```
   python web_security_scanner.py
   ```

2. Arayüzde "Hedef URL" alanına taramak istediğiniz web sitesinin URL'sini girin.

3. "Taramayı Başlat" butonuna tıklayın.

4. Tarama sonuçlarını "Güvenlik Açıkları" sekmesinde görüntüleyin.

## Katkıda Bulunma

Projeye katkıda bulunmak isterseniz, lütfen bir Pull Request açın. Büyük değişiklikler için önce bir konu açarak tartışmaya açmanızı rica ederiz.

## Lisans

Bu proje [MIT Lisansı](LICENSE) altında lisanslanmıştır.</code></pre>

    <h2>4. LICENSE</h2>
    <p>Projeniz için bir lisans seçin. MIT Lisansı yaygın bir seçenektir. MIT Lisansı metni için <a href="https://opensource.org/licenses/MIT" target="_blank">bu linki</a> kullanabilirsiniz.</p>

    <h2>5. .gitignore</h2>
    <p>Git'in izlemesini istemediğiniz dosyaları belirtir. Örnek içerik:</p>
    <pre><code># Python
__pycache__/
*.py[cod]
*$py.class

# Virtual Environment
venv/
env/

# PyInstaller
dist/
build/
*.spec

# PyCharm
.idea/

# OS generated files
.DS_Store
Thumbs.db</code></pre>

    <h2>6. CONTRIBUTING.md (opsiyonel)</h2>
    <p>Diğer geliştiricilere projenize nasıl katkıda bulunabileceklerini açıklar.</p>

    <h2>7. Kaynak klasörü</h2>
    <p>Örneğin <code>src/</code> veya <code>web_scanner/</code>. Eğer projeniz büyükse, kodunuzu organize etmek için bir kaynak klasörü oluşturabilirsiniz.</p>

    <h2>8. tests/ klasörü (opsiyonel)</h2>
    <p>Eğer birim testleriniz varsa, bunları bu klasörde tutabilirsiniz.</p>

    <h2>GitHub'a Yükleme Komutları</h2>
    <p>Bu dosyaları hazırladıktan sonra, GitHub'da yeni bir repo oluşturun ve şu komutları kullanarak projenizi yükleyin:</p>
    <pre><code>git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/kullaniciadi/web-guvenlik-tarayicisi.git
git push -u origin main</code></pre>

    <p>Bu yapı, projenizi profesyonel ve organize bir şekilde sunmanıza yardımcı olacak ve diğer geliştiricilerin projenizi anlamasını ve katkıda bulunmasını kolaylaştıracaktır.</p>
</body>
</html>
