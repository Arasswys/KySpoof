# KySpoof
WARNING ! PLEASE READ "README" FİLE!

==================================================
KYSPOOF - ADVANCED NETWORK SUITE
==================================================

Kyspoof, ag protokollerini test etmek, paket analizi yapmak ve IP/ARP/DNS spoofing gibi islemleri gerceklestirmek icin tasarlanmis gelismis bir siber guvenlik laboratuvar aracidir. Wireshark esintili arayuzu ve renkli log sistemiyle hem egitim hem de kendi aginizi test etmek icin idealdir.

--------------------------------------------------
!!! YASAL UYARI !!!
--------------------------------------------------
Bu arac SADECE kendi laboratuvarinizda ve yetkili oldugunuz aglarda kullanilmak uzere tasarlanmistir. Baskasinin agina veya cihazina karsi kullanmak TCK 243/244 kapsaminda SUC'TUR. Sorumluluk kullaniciya aittir.

--------------------------------------------------
1. CALISTIRMA (ONEMLI)
--------------------------------------------------
Bu arac bir Windows surucusu olan Npcap kullanir. Npcap yoksa IP Spoofing CALISMAZ.

* Npcap Kurulumu: Klasor icindeki "npcap-setup.exe" dosyasini calistirin. "Install Npcap" secenegini isaretleyip kurulumu tamamlayin.
* Yonetici Olarak Calistirma: "kyspoof.exe" dosyasina sag tiklayin ve "Yonetici olarak calistir" secenegini secin. Aksi halde ham paket gonderemezsiniz.
* Eger Wireshark kurduysaniz, Npcap zaten otomatik olarak kurulmus olabilir.

--------------------------------------------------
2. OZELLIKLER
--------------------------------------------------
* IP Spoofing: Sahte kaynak IP'li ICMP/TCP/UDP paketleri gonderme.
* ARP Spoofing: Yerel agda MITM (Man-in-the-Middle) saldirisi simulasyonu.
* DNS Spoofing: Kurban cihazin DNS sorgularini yakalayip sahte IP'ye yonlendirme.
* HTTP Istemci & Logger: Yerlesik Flask sunucusu ile gelen istekleri loglama.
* Port Tarayici: SYN taramasi ile acik portlari tespit etme.
* Wireshark Tarzi Paket Detayi: Ethernet, IP, TCP/UDP/ICMP ve Payload (Hex+ASCII) katmanlarini ayri ayri inceleme.
* Renkli Log Sistemi: Basarili, hata, uyari ve bilgi loglarini renkli goruntuleme.

--------------------------------------------------
3. NASIL KULLANILIR?
--------------------------------------------------

[ IP SPOOFING ]
1. Sol panelden "IP Spoof" sekmesini secin.
2. Kaynak IP: Sahte IP adresini girin (orn: 10.0.0.99 veya 240.0.0.1).
3. Hedef IP: Hedef cihazin IP'sini girin (orn: 192.168.1.1).
4. Protokol: ICMP, TCP veya UDP secin.
5. Payload: Gondermek istediginiz veriyi yazin.
6. "IP Enjekte Et" butonuna basin.
7. Wireshark'i acin ve paketin gittigini gorun!

[ ARP SPOOFING ]
1. Sol panelden "ARP Spoof" sekmesini secin.
2. Kurban IP: Zehirlemek istediginiz cihazin IP'sini girin.
3. Sahte Gateway: Modemin IP'sini girin (orn: 192.168.1.1).
4. "ARP Zehirle" butonuna basin.
5. Kurban cihazin trafigi artik sizin bilgisayarinizdan gecer.

[ DNS SPOOFING ]
1. Sol panelden "DNS Spoof" sekmesini secin.
2. Kurban IP: DNS sorgusunu yakalamak istediginiz cihazin IP'sini girin.
3. Sahte IP: Yonlendirmek istediginiz IP'yi girin.
4. "DNS Spoofing Baslat" butonuna basin ve "Dinlemeyi Baslat" ile sniffer'i aktif edin.

[ PORT TARAYICI ]
1. Sol panelden "Port Tarayici" sekmesini secin.
2. Hedef IP: Taranacak cihazin IP'sini girin.
3. Portlar: 21,22,80,443 veya 1-1000 gibi aralik yazin.
4. "Taramayi Baslat" butonuna basin.

[ HTTP LOGGER ]
1. Sol panelden "HTTP & Logger" sekmesini secin.
2. "Logger Sunucusunu Baslat" butonuna basin (Port 5000).
3. Hedef URL: http://192.168.1.12:5000/test gibi bir URL girin.
4. "HTTP Istegi Gonder" butonuna basin.
5. Logger, gelen istegin IP'sini, header'larini ve payload'unu loglar.

--------------------------------------------------
4. SIK SORULAN SORULAR
--------------------------------------------------

S: "IP Enjekte Et" butonuna bastim ama Wireshark'ta bir sey gorunmuyor.
C: Npcap kurulu mu kontrol edin. Programi yonetici olarak calistirdiginizdan emin olun. Dogru ag arayuzunu sectiginizden emin olun.

S: Paketler gidiyor ama cevap gelmiyor.
C: Bu normaldir. IP Spoofing tek yonlu bir paket enjeksiyonudur. Hedef sistem cevabi sahte IP'ye gonderir, o IP'de kimse olmadigi icin cevap kaybolur. Cevap almak istiyorsaniz kaynak IP'yi kendi gercek IP'niz yapin.

S: Npcap'i sildim, ne yapmaliyim?
C: Klasordeki "npcap-setup.exe" dosyasini calistirip yeniden kurun. Npcap olmadan bu arac CALISMAZ.

S: "Permission denied" hatasi aliyorum.
C: Programi yonetici olarak calistirmadiniz. Sag tik -> "Yonetici olarak calistir" yapin.

S: Hangi IP'leri kaynak olarak kullanabilirim?
C: 
- Guvenli (kendi aginiz): 10.0.0.99, 192.168.1.99
- Rezerve (hayalet): 240.0.0.1, 0.0.0.0
- Gercek ama sahipsiz: 192.0.2.1 (TEST-NET-1)
- KULLANMAYIN: 8.8.8.8, 1.1.1.1 gibi gercek sirketlere ait IP'ler (ISS filtrelerine takilir).

--------------------------------------------------
5. LISANS
--------------------------------------------------
Bu proje egitim amacli gelistirilmistir. Ticari kullanim icin lisans gereklidir.

Versiyon: v20.0
Son Guncelleme: 2026-10-24

==================================================
SON UYARI: Bu arac SADECE kendi laboratuvarinizda kullanilmak uzere tasarlanmistir. Baskasinin agina veya cihazina karsi kullanmak yasalara aykiridir.
==================================================
