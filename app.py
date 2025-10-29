# app.py KODU
import asyncio
import time
import re
import os
import random
import pickle  # Geçmiş için
import datetime  # Zaman damgası için
import threading
from telethon.sessions import StringSession
from telethon.sync import TelegramClient

from flask import Flask, render_template
from flask_socketio import SocketIO, emit

# app.py'de böyle olmalı:
api_id = os.environ.get('API_ID')
api_hash = os.environ.get('API_HASH')
session_string = os.environ.get('TELETHON_SESSION')

# --- Flask ve SocketIO Kurulumu ---
app = Flask(__name__)
# Gizli anahtar, sunucu oturumları için gereklidir
app.config['SECRET_KEY'] = 'cok-gizli-bir-anahtar!'
socketio = SocketIO(app)



# --- TARAMA VE GEÇMİŞ (DEĞİŞMEDİ) ---
TARAMA_LISTESI = [
    'AKBNK', 'ARCLK', 'ASELS', 'BIMAS', 'DOHOL', 'EKGYO', 'EREGL', 'FROTO', 'GARAN', 'GUBRF', 'HALKB', 'ISCTR', 'KCHOL',
    'KOZAA', 'KOZAL', 'KRDMD', 'MGROS', 'PETKM', 'PGSUS', 'SAHOL', 'SASA', 'SISE', 'SOKM', 'TAVHL', 'TCELL', 'THYAO',
    'TKFEN', 'TOASO', 'TTKOM', 'TUPRS', 'ULKER', 'VAKBN', 'YKBNK'
]
HISTORY_FILE = os.path.join(DATA_DIR, "query_history.pkl")
history_list = []


# load_history() ve save_history() fonksiyonları değişmedi
def load_history():
    global history_list
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "rb") as f:
                history_list = pickle.load(f)
        except Exception as e:
            print(f"Geçmiş yüklenirken hata: {e}")
            history_list = []
    else:
        history_list = []


def save_history():
    try:
        with open(HISTORY_FILE, "wb") as f:
            pickle.dump(history_list, f)
    except Exception as e:
        print(f"Geçmiş kaydedilirken hata: {e}")


def add_to_history(new_entry):
    global history_list
    history_list.insert(0, new_entry)
    history_list = history_list[:10]  # Son 10'u tut
    save_history()
    # Geçmiş penceresi web'de farklı ele alınacak, bu yüzden GUI güncellemesi kaldırıldı.


# AI_PROMPT (Şimdilik web'de kullanılmıyor, ancak mantık sunucuda kalabilir)
AI_PROMPT = """(PROMPT METNİ KISALTILDI)"""


# --- VERİ ÇEKME FONKSİYONLARI (GÜNCELLENDİ) ---
# 'window.after' ve 'status_var' güncellemeleri kaldırıldı.
# Onun yerine bir 'status_callback' fonksiyonu alacaklar.

async def fetch_data(client, hisse_kodu, zaman_araligi, data_type, status_callback):
    message_ids = []
    price_info = None
    try:
        command = f"/{data_type} {hisse_kodu}"
        son_gonderilen_mesaj = await client.send_message(bot_username, command)
        message_ids.append(son_gonderilen_mesaj.id)
        butonlu_mesaj = None
        for i in range(120):
            # GÜNCELLENDİ: Durum güncellemesi web'e gönderilir
            status_callback(f"({hisse_kodu}) {zaman_araligi} için botun cevabı bekleniyor{'.' * (i % 4)}")
            time.sleep(0.25)
            messages = await client.get_messages(bot_username, limit=1)
            if messages and messages[0].id > son_gonderilen_mesaj.id and messages[0].reply_markup:
                butonlu_mesaj = messages[0];
                message_ids.append(butonlu_mesaj.id);
                break
        if not butonlu_mesaj: return {"hata": "Bot'tan periyot seçenekleri alınamadı.", "ids": message_ids}
        orjinal_metin = butonlu_mesaj.text
        await butonlu_mesaj.click(text=zaman_araligi)
        veri_mesaji = None
        for i in range(120):
            # GÜNCELLENDİ: Durum güncellemesi web'e gönderilir
            status_callback(f"({hisse_kodu}) {zaman_araligi} verisi bekleniyor{'.' * (i % 4)}")
            time.sleep(0.25)
            latest_message = (await client.get_messages(bot_username, limit=1))[0]
            if latest_message.id > butonlu_mesaj.id or (
                    latest_message.id == butonlu_mesaj.id and latest_message.text != orjinal_metin):
                veri_mesaji = latest_message;
                if veri_mesaji.id not in message_ids: message_ids.append(veri_mesaji.id)
                break
        if not veri_mesaji: return {"hata": f"'{zaman_araligi}' için veri mesajı zaman aşımına uğradı.",
                                    "ids": message_ids}
        if data_type == 'akd' and zaman_araligi == 'Günlük':
            try:
                price_info = veri_mesaji.text.splitlines()[0].split(' ', 1)[1]
            except IndexError:
                price_info = "N/A"
        satirlar = veri_mesaji.text.splitlines()
        data = {"grup1": [], "grup2": []}

        # ... (Veri ayrıştırma mantığı (Regex) değişmedi) ...
        if data_type == 'takas' and 'Son Takas' in zaman_araligi:
            aktif_bolum = "grup1"
            for satir in satirlar:
                match_normal = re.match(r"(\d+)\.\s(.+?)\s([\d.,]+\s\w+)\s(%[\d.,]+)", satir.strip())
                match_diger = re.match(r"(Diğer\s\(.+?\))\s([\d.,]+\s\w+)\s(%[\d.,]+)", satir.strip())
                if match_normal:
                    sira, kurum, lot, pay = match_normal.groups();
                    data[aktif_bolum].append((sira, kurum.strip(), lot.strip(), pay.strip()))
                elif match_diger:
                    kurum, lot, pay = match_diger.groups();
                    data[aktif_bolum].append(("-", kurum.strip(), lot.strip(), pay.strip()))
        else:
            aktif_bolum = None
            for satir in satirlar:
                if any(s in satir for s in ['Net Alım Yapanlar', 'Takası Artanlar']): aktif_bolum = "grup1"
                if any(s in satir for s in ['Net Satım Yapanlar', 'Takası Azaltanlar']): aktif_bolum = "grup2"
                match = re.match(r"(\d+)\.\s(.+?)\s→\s([-,.+%\d\s\w]+?)\s*(?:\((.+?)\))?$", satir.strip())
                if match and aktif_bolum:
                    sira, kurum, lot_veya_fark, parantez_ici = match.groups()
                    data[aktif_bolum].append(
                        (sira, kurum.strip(), lot_veya_fark.strip(), parantez_ici if parantez_ici else "-"))

        return {"data": data, "ids": message_ids, "price_info": price_info}
    except Exception as e:
        return {"hata": f"Bir hata oluştu: {e}", "ids": message_ids}


async def fetch_price_only(client, hisse_kodu, status_callback):
    result = await fetch_data(client, hisse_kodu, "Günlük", "akd", status_callback)
    price_info = result.get("price_info", "Alınamadı")
    return {"data": result.get("data"),
            "ids": result.get("ids", []),
            "price_info": f"{hisse_kodu.upper()} Güncel Fiyat: {price_info}",
            "is_price_only": True}


async def fetch_depth_data(client, hisse_kodu, status_callback):
    message_ids = []
    try:
        command = f"/derinlik {hisse_kodu}"
        son_gonderilen_mesaj = await client.send_message(bot_username, command)
        message_ids.append(son_gonderilen_mesaj.id)
        ilk_yanit_mesaji = None
        for i in range(120):
            # GÜNCELLENDİ: Durum güncellemesi web'e gönderilir
            status_callback(f"({hisse_kodu}) Derinlik bekleniyor{'.' * (i % 4)}")
            time.sleep(0.25)
            messages = await client.get_messages(bot_username, limit=1)
            if messages and messages[0].id > son_gonderilen_mesaj.id:
                ilk_yanit_mesaji = messages[0];
                message_ids.append(ilk_yanit_mesaji.id);
                break
        if not ilk_yanit_mesaji:
            return {"hata": "Bot'tan derinlik için ilk yanıt alınamadı.", "ids": message_ids}
        orjinal_metin = ilk_yanit_mesaji.text
        veri_mesaji = None
        if ("Toplam Alış Lot:" in orjinal_metin or "Toplam Satış Lot:" in orjinal_metin):
            veri_mesaji = ilk_yanit_mesaji
        else:
            for i in range(120):
                # GÜNCELLENDİ: Durum güncellemesi web'e gönderilir
                status_callback(f"({hisse_kodu}) Veri bekleniyor{'.' * (i % 4)}")
                time.sleep(0.25)
                latest_message = (await client.get_messages(bot_username, limit=1))[0]
                if latest_message.id > ilk_yanit_mesaji.id or (
                        latest_message.id == ilk_yanit_mesaji.id and latest_message.text != orjinal_metin):
                    veri_mesaji = latest_message;
                    if veri_mesaji.id not in message_ids:
                        message_ids.append(veri_mesaji.id)
                    break
        if not veri_mesaji:
            return {"hata": "Derinlik verisi zaman aşımına uğradı.", "ids": message_ids}

        # ... (Derinlik veri ayrıştırması değişmedi) ...
        text = veri_mesaji.text
        text_lines = text.splitlines()
        fiyat, saat, alis_lot, satis_lot = "-", "-", 0, 0
        if text_lines:
            match_fiyat = re.search(r"\S+\s(.+)", text_lines[0])
            if match_fiyat:
                fiyat = match_fiyat.group(1)
        for line in text_lines:
            if "Toplam Alış Lot:" in line:
                match = re.search(r'([\d.,]+)', line)
                if match:
                    alis_lot = int(match.group(1).replace(".", "").replace(",", ""))
            elif "Toplam Satış Lot:" in line:
                match = re.search(r'([\d.,]+)', line)
                if match:
                    satis_lot = int(match.group(1).replace(".", "").replace(",", ""))
            elif "Son işlem saati:" in line:
                match = re.search(r'([\d:]+)', line)
                if match:
                    saat = match.group(1)

        return {"alis_lot": alis_lot, "satis_lot": satis_lot, "saat": saat, "fiyat": fiyat, "ids": message_ids}
    except Exception as e:
        return {"hata": f"Derinlik verisi alınırken hata oluştu: {e}", "ids": message_ids}


# --- WEB ARAYÜZÜ İÇİN GEREKLİ TÜM GÖRSEL KODLAR KALDIRILDI ---
# (create_and_display_table, create_and_display_depth, save_results_to_file vb. kaldırıldı)
# (SplashScreen, HistoryWindow, ScannerWindow sınıfları kaldırıldı)
# (Tüm ctk ve tk ana arayüz kurulum kodları kaldırıldı)
# ...
# ...


# --- YENİ: VERİ ÇEKME İŞ PARÇACIĞI (WEBSOCKET İÇİN UYARLANDI) ---
def run_fetch_logic(params):
    """
    Bu fonksiyon, SocketIO tarafından bir arka plan thread'inde çalıştırılacak.
    Tüm 'window.after' çağrıları 'socketio.emit' ile değiştirildi.
    """

    # 1. Parametreleri al
    hisse_listesi = params.get("hisse_listesi", [])
    fiyat_secili = params.get("fiyat_secili", False)
    akd_secilenler = params.get("akd_secilenler", [])
    takas_secilenler = params.get("takas_secilenler", [])
    derinlik_secili = params.get("derinlik_secili", False)

    if not hisse_listesi:
        socketio.emit('status_update', {'msg': 'Hata: Hisse listesi boş.', 'color': 'red'})
        return

    toplam_baslangic = time.time()
    all_message_ids_to_delete = []
    current_query_results = []  # Geçmiş kaydı için (bu mantık korundu)

    # Durum güncellemelerini web'e göndermek için bir yardımcı fonksiyon
    def status_callback(msg):
        socketio.emit('status_update', {'msg': msg, 'color': 'gray'})

    async def main_async_logic():
        # 'hisse_session' dosyası yerine 'session_string' kullanıyoruz
        async with TelegramClient(StringSession(session_string), api_id, api_hash) as client:
            fiyat_gosterildi = set()
            for i, hisse_kodu in enumerate(hisse_listesi):
                if i > 0:
                    # Arayüzde ayırıcı çizgi göster
                    socketio.emit('new_separator')

                socketio.emit('status_update', {
                    'msg': f"İşleniyor: {hisse_kodu} ({i + 1}/{len(hisse_listesi)})",
                    'color': 'white'
                })

                if derinlik_secili:
                    result = await fetch_depth_data(client, hisse_kodu, status_callback)
                    all_message_ids_to_delete.extend(result.get("ids", []))
                    current_query_results.append({
                        "type": "depth", "hisse": hisse_kodu, "data": result
                    })
                    # GÜNCELLENDİ: Veriyi web'e gönder
                    socketio.emit('new_data', {'type': 'depth', 'hisse': hisse_kodu, 'data': result})

                if fiyat_secili and not akd_secilenler and not takas_secilenler:
                    result = await fetch_price_only(client, hisse_kodu, status_callback)
                    all_message_ids_to_delete.extend(result.get("ids", []))
                    current_query_results.append({
                        "type": "price", "hisse": hisse_kodu, "period": "Günlük", "data": result
                    })
                    # GÜNCELLENDİ: Veriyi web'e gönder
                    socketio.emit('new_data', {
                        'type': 'price_only',
                        'hisse': hisse_kodu,
                        'data': result
                    })
                    continue

                if (derinlik_secili and akd_secilenler) or (derinlik_secili and takas_secilenler):
                    socketio.emit('new_separator')

                if akd_secilenler:
                    for zaman in akd_secilenler:
                        result = await fetch_data(client, hisse_kodu, zaman, 'akd', status_callback)
                        all_message_ids_to_delete.extend(result.get("ids", []))
                        current_query_results.append({
                            "type": "akd", "hisse": hisse_kodu, "period": zaman, "data": result
                        })
                        price_info_to_display = result.get("price_info") if (
                                                                                    fiyat_secili or zaman == 'Günlük') and hisse_kodu not in fiyat_gosterildi else None
                        if price_info_to_display: fiyat_gosterildi.add(hisse_kodu)
                        title = f"{hisse_kodu} {zaman} AKD VERİLERİ"
                        # GÜNCELLENDİ: Veriyi web'e gönder
                        socketio.emit('new_data', {
                            'type': 'table',
                            'data_type': 'akd',
                            'period': zaman,
                            'title': title,
                            'result_data': result,
                            'price_info': price_info_to_display
                        })

                if akd_secilenler and takas_secilenler:
                    socketio.emit('new_separator')

                if takas_secilenler:
                    if fiyat_secili and hisse_kodu not in fiyat_gosterildi:
                        price_result = await fetch_price_only(client, hisse_kodu, status_callback)
                        all_message_ids_to_delete.extend(price_result.get("ids", []))
                        current_query_results.append({
                            "type": "price", "hisse": hisse_kodu, "period": "Günlük", "data": price_result
                        })
                        if "price_info" in price_result:
                            # GÜNCELLENDİ: Veriyi web'e gönder
                            socketio.emit('new_data', {
                                'type': 'price_only',
                                'hisse': hisse_kodu,
                                'data': price_result
                            })
                            fiyat_gosterildi.add(hisse_kodu)

                    for zaman in takas_secilenler:
                        result = await fetch_data(client, hisse_kodu, zaman, 'takas', status_callback)
                        all_message_ids_to_delete.extend(result.get("ids", []))
                        current_query_results.append({
                            "type": "takas", "hisse": hisse_kodu, "period": zaman, "data": result
                        })
                        title = f"{hisse_kodu} {zaman} TAKAS VERİLERİ"
                        # GÜNCELLENDİ: Veriyi web'e gönder
                        socketio.emit('new_data', {
                            'type': 'table',
                            'data_type': 'takas',
                            'period': zaman,
                            'title': title,
                            'result_data': result,
                            'price_info': None
                        })

            if all_message_ids_to_delete:
                socketio.emit('status_update', {'msg': 'Sohbet geçmişi temizleniyor...', 'color': 'gray'})
                unique_ids = list(set(all_message_ids_to_delete))
                await client.delete_messages(bot_username, unique_ids, revoke=True)

    # Async mantığı çalıştır
    asyncio.run(main_async_logic())

    # --- GEÇMİŞE EKLEME (DEĞİŞMEDİ) ---
    # get_results_as_text() fonksiyonu artık yok, bu yüzden 'full_text_output' geçici olarak boş.
    # Bu özellik (geçmişten tam metin okuma) web'de yeniden tasarlanmalı.
    history_entry = {
        "timestamp": datetime.datetime.now(),
        "parameters": params,  # 'params' dict'ini doğrudan kaydediyoruz
        "structured_data": current_query_results,
        "full_text_output": "Web'den kaydedildi - Metin çıktısı devrede dışı."
    }
    add_to_history(history_entry)
    # --- BİTTİ ---

    toplam_bitis = time.time()
    toplam_sure = toplam_bitis - toplam_baslangic

    # İşlemin bittiğini web'e bildir
    socketio.emit('fetch_complete', {
        'status_msg': 'Tüm işlemler tamamlandı.',
        'duration_msg': f'Toplam süre: {toplam_sure:.2f} saniye'
    })


# --- YENİ: FLASK VE SOCKETIO ROTALARI ---

@app.route('/')
def index():
    """Ana sayfayı (index.html) sunar."""
    # 'Hoşgeldin Musab' ekranı (SplashScreen) burada yok.
    # HTML sayfası kendi "yükleniyor" animasyonunu içerecek.
    return render_template('index.html')


@socketio.on('connect')
def handle_connect():
    """Bir kullanıcı web sitesine bağlandığında tetiklenir."""
    print('Bir istemci bağlandı')
    # Program başlarken geçmişi diskten yükle
    load_history()


@socketio.on('start_fetch')
def handle_start_fetch(data):
    """
    Kullanıcı web sayfasındaki 'Verileri Getir' butonuna tıkladığında
    JavaScript'ten bu 'start_fetch' olayı tetiklenir.
    'data' içinde hisse listesi ve seçenekler bulunur.
    """

    # Gelen veriyi (string listesi) işle
    hisse_input = data.get('hisse_input', '')
    hisse_listesi = [h.strip().upper() for h in hisse_input.split(',') if h.strip()]

    # Arama parametrelerini bir dict'te topla
    query_params = {
        "hisse_listesi_str": hisse_input,
        "hisse_listesi": hisse_listesi,
        "akd_secilenler": data.get("akd_secilenler", []),
        "takas_secilenler": data.get("takas_secilenler", []),
        "derinlik_secili": data.get("derinlik_secili", False),
        "fiyat_secili": data.get("fiyat_secili", False)
    }

    # Uzun süren veri çekme işini ana thread'i kilitlememek için
    # bir arka plan görevinde (thread) başlat.
    socketio.start_background_task(target=run_fetch_logic, params=query_params)


# --- Sunucuyu Başlatma ---
# --- Sunucuyu Başlatma (Render için ayarlandı) ---
if __name__ == '__main__':
    # Render, 'PORT' adında bir çevre değişkeni sağlar
    port = int(os.environ.get('PORT', 5000))
    # 'debug=True' sunucuda kapalı olmalı
    # 'host='0.0.0.0'' tüm IP'lerden gelen bağlantıları kabul eder (Render için şart)
    print(f"Sunucu http://0.0.0.0:{port} adresinde başlatılıyor...")
    socketio.run(app, debug=False, host='0.0.0.0', port=port)