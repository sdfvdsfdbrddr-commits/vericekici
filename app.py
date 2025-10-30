import asyncio
import time
import re
import os
import pickle
import datetime
import threading
from telethon.sync import TelegramClient
from telethon.sessions import StringSession

from flask import (Flask, render_template, request, redirect, url_for,
                   abort, session, flash, g)
from flask_socketio import SocketIO, emit
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         login_required, current_user)
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# --- KENDİ BİLGİLERİN (Sunucudan Çekilecek) ---
api_id = os.environ.get('API_ID')
api_hash = os.environ.get('API_HASH')
session_string = os.environ.get('TELETHON_SESSION')
bot_username = os.environ.get('BOT_USERNAME')

# --- YENİ: VERİTABANI BAĞLANTISI ---
DATABASE_URL = os.environ.get('DATABASE_URL')

# --- Flask ve SocketIO Kurulumu ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'cok-gizli-bir-anahtar-daha-ekle')

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Lütfen yönetici panelini görmek için giriş yapın."
login_manager.session_protection = "strong"

socketio = SocketIO(app)


# --- YENİ: YÖNETİCİ GİRİŞ MODELİ ---
class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    password_hash = db.Column(db.String(256))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


@login_manager.user_loader
def load_user(user_id):
    try:
        with app.app_context():
            return db.session.get(Admin, int(user_id))
    except Exception as e:
        print(f"load_user error: {e}")
        return None


# --- YENİ: IP İZİN MODELİ (CİHAZ BİLGİSİ EKLENDİ) ---
class AllowedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), unique=True, nullable=False)
    status = db.Column(db.String(20), nullable=False)  # 'accepted', 'blocked', 'pending'
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    # YENİ SÜTUN: Cihaz bilgisi (User-Agent)
    user_agent = db.Column(db.String(255), nullable=True)


# --- YENİ: İLK YÖNETİCİYİ OLUŞTURMA ---
def create_first_admin():
    try:
        with app.app_context():
            db.create_all()  # Tüm tabloları oluştur
            if not Admin.query.filter_by(username='musab').first():
                print("İlk yönetici (musab) oluşturuluyor...")
                admin_user = Admin(username='musab')
                admin_user.set_password('kaan')  # Şifre: kaan
                db.session.add(admin_user)
                db.session.commit()
                print("Yönetici oluşturuldu.")
            else:
                print("Yönetici zaten mevcut.")
    except Exception as e:
        print(f"Veritabanı veya yönetici oluşturulurken hata oluştu: {e}")


# --- YENİ: IP KONTROL SİSTEMİ (GÜNCELLENDİ) ---
def get_user_ip():
    if 'X-Forwarded-For' in request.headers:
        return request.headers['X-Forwarded-For'].split(',')[0].strip()
    return request.remote_addr


def ip_whitelist_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_ip = get_user_ip()
        g.user_ip = user_ip

        # GÜNCELLENDİ: Eğer yönetici giriş yapmışsa, IP'ye bakma, direk izin ver.
        if current_user.is_authenticated:
            return f(*args, **kwargs)

        try:
            ip_entry = AllowedIP.query.filter_by(ip_address=user_ip).first()

            if ip_entry and ip_entry.status == 'accepted':
                return f(*args, **kwargs)

            if ip_entry and ip_entry.status == 'blocked':
                return render_template('reject.html', user_ip=user_ip,
                                       message="IP adresiniz yönetici tarafından engellenmiştir.")

            if ip_entry and ip_entry.status == 'pending':
                return render_template('reject.html', user_ip=user_ip, message="İsteğiniz zaten gönderildi, beklemede.")

            # IP listede hiç yoksa, 'reject.html'i göster (IP ile birlikte)
            return render_template('reject.html', user_ip=user_ip)

        except Exception as e:
            print(f"IP KONTROL HATASI (Veritabanı uyanıyor olabilir): {e}")
            return render_template('reject.html', user_ip=user_ip,
                                   message="Veritabanı hatası. Lütfen 1 dakika sonra tekrar deneyin.")

    return decorated_function


# --- ESKİ VERİ ÇEKME KODU (DEĞİŞMEDİ) ---
# (Tüm fetch_data, fetch_price_only, fetch_depth_data fonksiyonları)
async def fetch_data(client, hisse_kodu, zaman_araligi, data_type, status_callback):
    message_ids = []
    price_info = None
    try:  # <-- TRY BLOĞU BURADA BAŞLIYOR
        command = f"/{data_type} {hisse_kodu}"
        son_gonderilen_mesaj = await client.send_message(bot_username, command)
        message_ids.append(son_gonderilen_mesaj.id)
        butonlu_mesaj = None
        for i in range(120):
            status_callback(f"({hisse_kodu}) {zaman_araligi} için botun cevabı bekleniyor{'.' * (i % 4)}")
            await asyncio.sleep(0.25)
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
            status_callback(f"({hisse_kodu}) {zaman_araligi} verisi bekleniyor{'.' * (i % 4)}")
            await asyncio.sleep(0.25)
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
        return {"data": data, "ids": message_ids,
                "price_info": price_info}  # <-- HATALI SATIR BUYDU, TRY bloğunun içindeydi.
    except Exception as e:  # <-- EXCEPT BLOĞU BURAYA EKLENDİ
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
            status_callback(f"({hisse_kodu}) Derinlik bekleniyor{'.' * (i % 4)}")
            await asyncio.sleep(0.25)
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
                status_callback(f"({hisse_kodu}) Veri bekleniyor{'.' * (i % 4)}")
                await asyncio.sleep(0.25)
                latest_message = (await client.get_messages(bot_username, limit=1))[0]
                if latest_message.id > ilk_yanit_mesaji.id or (
                        latest_message.id == ilk_yanit_mesaji.id and latest_message.text != orjinal_metin):
                    veri_mesaji = latest_message;
                    if veri_mesaji.id not in message_ids:
                        message_ids.append(veri_mesaji.id)
                    break
        if not veri_mesaji:
            return {"hata": "Derinlik verisi zaman aşımına uğradı.", "ids": message_ids}

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


# Async iş parçacığı (değişmedi)
def run_fetch_logic(params):
    def status_callback(msg):
        socketio.emit('status_update', {'msg': msg, 'color': 'gray'})

    async def main_async_logic():
        if not all([api_id, api_hash, session_string, bot_username]):
            print("HATA: Gizli değişkenler (API_ID, API_HASH, TELETHON_SESSION, BOT_USERNAME) eksik.")
            status_callback("Sunucu hatası: Lütfen yöneticiyle iletişime geçin.")
            return

        try:
            async with TelegramClient(StringSession(session_string), api_id, api_hash) as client:
                hisse_listesi = params.get("hisse_listesi", [])
                fiyat_secili = params.get("fiyat_secili", False)
                akd_secilenler = params.get("akd_secilenler", [])
                takas_secilenler = params.get("takas_secilenler", [])
                derinlik_secili = params.get("derinlik_secili", False)

                fiyat_gosterildi = set()
                all_message_ids_to_delete = []

                for i, hisse_kodu in enumerate(hisse_listesi):
                    if i > 0:
                        socketio.emit('new_separator')

                    socketio.emit('status_update', {
                        'msg': f"İşleniyor: {hisse_kodu} ({i + 1}/{len(hisse_listesi)})",
                        'color': 'white'
                    })

                    if derinlik_secili:
                        result = await fetch_depth_data(client, hisse_kodu, status_callback)
                        all_message_ids_to_delete.extend(result.get("ids", []))
                        socketio.emit('new_data', {'type': 'depth', 'hisse': hisse_kodu, 'data': result})

                    if fiyat_secili and not akd_secilenler and not takas_secilenler:
                        result = await fetch_price_only(client, hisse_kodu, status_callback)
                        all_message_ids_to_delete.extend(result.get("ids", []))
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
                            price_info_to_display = result.get("price_info") if (
                                                                                        fiyat_secili or zaman == 'Günlük') and hisse_kodu not in fiyat_gosterildi else None
                            if price_info_to_display: fiyat_gosterildi.add(hisse_kodu)
                            title = f"{hisse_kodu} {zaman} AKD VERİLERİ"
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
                            if "price_info" in price_result:
                                socketio.emit('new_data', {
                                    'type': 'price_only',
                                    'hisse': hisse_kodu,
                                    'data': price_result
                                })
                                fiyat_gosterildi.add(hisse_kodu)

                        for zaman in takas_secilenler:
                            result = await fetch_data(client, hisse_kodu, zaman, 'takas', status_callback)
                            all_message_ids_to_delete.extend(result.get("ids", []))
                            title = f"{hisse_kodu} {zaman} TAKAS VERİLERİ"
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

        except Exception as e:
            print(f"Telegram Hatası: {e}")
            status_callback(f"Telegram Hatası: {e}")

    toplam_baslangic = time.time()
    try:
        asyncio.run(main_async_logic())
    except Exception as e:
        print(f"Asyncio Hatası: {e}")
        socketio.emit('status_update', {'msg': f"Sunucu Hatası: {e}", 'color': 'red'})

    toplam_bitis = time.time()
    toplam_sure = toplam_bitis - toplam_baslangic

    socketio.emit('fetch_complete', {
        'status_msg': 'Tüm işlemler tamamlandı.',
        'duration_msg': f'Toplam süre: {toplam_sure:.2f} saniye'
    })


# --- YENİ: WEB SAYFASI ROTALARI (ROUTES) ---

@app.route('/')
@ip_whitelist_required
def index():
    """Ana hisse senedi aracını sunar (index.html)."""
    return render_template('index.html')


@app.route('/request-access', methods=['GET', 'POST'])
def request_access():
    """İstek gönderme sayfası ve mantığı."""
    user_ip = get_user_ip()

    if request.method == 'POST':
        # GÜNCELLENDİ: Cihaz bilgisini (User-Agent) al
        user_agent_string = request.headers.get('User-Agent', 'Bilinmiyor')

        existing_ip = AllowedIP.query.filter_by(ip_address=user_ip).first()
        if not existing_ip:
            # GÜNCELLENDİ: user_agent'i veritabanına kaydet
            new_request = AllowedIP(ip_address=user_ip,
                                    status='pending',
                                    timestamp=datetime.datetime.utcnow(),
                                    user_agent=user_agent_string)
            db.session.add(new_request)
            db.session.commit()
            return render_template('reject.html', user_ip=user_ip,
                                   message="İsteğiniz başarıyla alındı. Yönetici onayı bekleniyor.")
        elif existing_ip.status == 'blocked':
            return render_template('reject.html', user_ip=user_ip,
                                   message="IP adresiniz yönetici tarafından engellenmiştir.")
        else:
            return render_template('reject.html', user_ip=user_ip,
                                   message="Zaten bir isteğiniz var veya IP'niz zaten kabul edilmiş.")

    # IP listede hiç yoksa (GET request), reject.html'i göster (IP ile birlikte)
    return render_template('reject.html', user_ip=user_ip)


# --- YENİ: YÖNETİCİ PANELİ ROTALARI ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Yönetici giriş sayfası (login.html)."""
    if current_user.is_authenticated:
        return redirect(url_for('admin_panel'))

    if request.method == 'POST':
        password = request.form['password']
        admin_user = Admin.query.filter_by(username='musab').first()

        if admin_user and admin_user.check_password(password):
            login_user(admin_user)
            session.permanent = True
            app.permanent_session_lifetime = datetime.timedelta(days=30)
            return redirect(url_for('admin_panel'))
        else:
            return render_template('login.html', error="Geçersiz şifre.")

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/admin')
@login_required
def admin_panel():
    """Yönetici panelini (admin.html) gösterir."""
    pending_ips = AllowedIP.query.filter_by(status='pending').order_by(AllowedIP.timestamp.desc()).all()
    accepted_ips = AllowedIP.query.filter_by(status='accepted').order_by(AllowedIP.ip_address).all()
    blocked_ips = AllowedIP.query.filter_by(status='blocked').order_by(AllowedIP.ip_address).all()

    return render_template('admin.html',
                           pending=pending_ips,
                           accepted=accepted_ips,
                           blocked=blocked_ips)


@app.route('/admin/handle-request', methods=['POST'])
@login_required
def handle_request():
    """Bekleyen istekleri (Kabul Et, Reddet, Engelle) işler."""
    ip_addr = request.form['ip']
    action = request.form['action']

    ip_entry = AllowedIP.query.filter_by(ip_address=ip_addr).first()
    if not ip_entry:
        abort(404)

    if action == 'accept':
        ip_entry.status = 'accepted'
        ip_entry.timestamp = datetime.datetime.utcnow()
    elif action == 'block':
        ip_entry.status = 'blocked'
        ip_entry.timestamp = datetime.datetime.utcnow()
    elif action == 'reject':
        db.session.delete(ip_entry)

    db.session.commit()
    return redirect(url_for('admin_panel'))


@app.route('/admin/manual-add', methods=['POST'])
@login_required
def manual_add():
    """Yöneticinin manuel IP eklemesini sağlar."""
    ip_addr = request.form['ip'].strip()
    if not ip_addr:
        return redirect(url_for('admin_panel'))

    existing_ip = AllowedIP.query.filter_by(ip_address=ip_addr).first()

    if existing_ip:
        existing_ip.status = 'accepted'
        existing_ip.timestamp = datetime.datetime.utcnow()
        # GÜNCELLENDİ: Eğer cihaz bilgisi yoksa, manuel olarak ekle
        existing_ip.user_agent = existing_ip.user_agent or "Manuel Eklendi"
    else:
        # GÜNCELLENDİ: user_agent'i manuel olarak ekle
        new_ip = AllowedIP(ip_address=ip_addr,
                           status='accepted',
                           timestamp=datetime.datetime.utcnow(),
                           user_agent="Manuel Eklendi")
        db.session.add(new_ip)

    db.session.commit()
    return redirect(url_for('admin_panel'))


@app.route('/admin/remove-accepted', methods=['POST'])
@login_required
def remove_accepted():
    ip_addr = request.form['ip']
    ip_entry = AllowedIP.query.filter_by(ip_address=ip_addr, status='accepted').first()
    if ip_entry:
        db.session.delete(ip_entry)
        db.session.commit()
    return redirect(url_for('admin_panel'))


@app.route('/admin/unblock', methods=['POST'])
@login_required
def unblock():
    ip_addr = request.form['ip']
    ip_entry = AllowedIP.query.filter_by(ip_address=ip_addr, status='blocked').first()
    if ip_entry:
        db.session.delete(ip_entry)
        db.session.commit()
    return redirect(url_for('admin_panel'))


# --- YENİ: SOCKETIO (Veri Çekme) ROTALARI ---

@socketio.on('connect')
@ip_whitelist_required
def handle_connect():
    print(f'İzin verilen istemci ({g.user_ip}) bağlandı')


@socketio.on('start_fetch')
@ip_whitelist_required
def handle_start_fetch(data):
    hisse_input = data.get('hisse_input', '')
    hisse_listesi = [h.strip().upper() for h in hisse_input.split(',') if h.strip()]

    query_params = {
        "hisse_listesi_str": hisse_input,
        "hisse_listesi": hisse_listesi,
        "akd_secilenler": data.get("akd_secilenler", []),
        "takas_secilenler": data.get("takas_secilenler", []),
        "derinlik_secili": data.get("derinlik_secili", False),
        "fiyat_secili": data.get("fiyat_secili", False)
    }

    socketio.start_background_task(target=run_fetch_logic, params=query_params)


# --- Sunucuyu Başlatma ---
if __name__ == '__main__':
    with app.app_context():
        create_first_admin()

    port = int(os.environ.get('PORT', 5000))
    print(f"Sunucu http://0.0.0.0:{port} adresinde başlatılıyor...")
    socketio.run(app, debug=False, host='0.0.0.0', port=port, allow_unsafe_werkzeug=True)