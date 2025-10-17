#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tracking Pixel Server - Raspberry Pi Uyumlu
FastAPI tabanlı asenkron, performanslı ve güvenli tracking server
"""

from fastapi import FastAPI, Request, Response, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse, RedirectResponse, HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from contextlib import asynccontextmanager
import uvicorn
import io
import json
import logging
from datetime import datetime
from PIL import Image
from typing import Dict, Optional
from pydantic import BaseModel, EmailStr
import asyncio
from user_agents import parse as parse_user_agent
import requests
from tracking_database import TrackingDatabase

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('tracking_server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Database
db = TrackingDatabase()

# Config - Railway environment variables veya local config.json
import os

# Railway environment variables kontrolü
if os.getenv('RAILWAY_ENVIRONMENT'):
    # Railway deployment - Environment variables kullan
    CONFIG = {
        "main_pc_api_url": os.getenv("MAIN_API_URL", "http://localhost:8000"),
        "main_pc_api_key": os.getenv("API_KEY", "b2b_cetei_secure_key_2024")
    }
    logger.info("🚂 Railway environment variables yüklendi")
else:
    # Local development - config.json kullan
    try:
        with open("config.json", "r", encoding='utf-8') as f:
            CONFIG = json.load(f)
        logger.info("💻 Local config.json yüklendi")
    except Exception as e:
        logger.error(f"Config yükleme hatası: {e}")
        CONFIG = {}

MAIN_API_URL = CONFIG.get("main_pc_api_url", "http://localhost:8000")
API_KEY = CONFIG.get("main_pc_api_key", "b2b_cetei_secure_key_2024")

# Lifespan event handler (modern FastAPI)
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Server başlatma ve kapatma işlemleri"""
    # Startup
    import os
    is_railway = os.getenv('RAILWAY_ENVIRONMENT') is not None
    
    logger.info("=" * 80)
    logger.info("🚀 TRACKING PIXEL SERVER BAŞLATILIYOR")
    logger.info("=" * 80)
    logger.info(f"📊 Database: tracking.db")
    logger.info(f"{'🚂 Mode: Railway Cloud Deployment' if is_railway else '💻 Mode: Windows PC Local'}")
    logger.info(f"⚡ Async: Enabled")
    logger.info(f"📡 Ana API: {MAIN_API_URL} (opsiyonel)")
    if is_railway:
        logger.info(f"🌐 Railway Project ID: {os.getenv('RAILWAY_PROJECT_ID', 'N/A')}")
        logger.info(f"🔧 Railway Environment: {os.getenv('RAILWAY_ENVIRONMENT_NAME', 'production')}")
    logger.info("=" * 80)
    logger.info("✅ Server hazır!")
    
    yield
    
    # Shutdown
    logger.info("🛑 Server kapatılıyor...")
    global db
    if db:
        db.close()
    logger.info("✅ Database bağlantısı kapatıldı")

# FastAPI App
app = FastAPI(
    title="B2B Tracking Pixel Server",
    description="Windows PC - Asenkron email tracking sistemi",
    version="2.0.0",
    lifespan=lifespan
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Gzip Compression (Raspberry Pi bandwidth tasarrufu)
app.add_middleware(GZipMiddleware, minimum_size=1000)


# ==================== PYDANTIC MODELS ====================

class EmailRegistration(BaseModel):
    tracking_id: str
    firm_id: str
    to_email: EmailStr
    subject: str
    body: str = ""
    sent_at: Optional[str] = None


class UnsubscribeRequest(BaseModel):
    email: EmailStr
    firm_id: str
    reason: Optional[str] = None


# ==================== HELPER FUNCTIONS ====================

def create_transparent_pixel() -> bytes:
    """1x1 transparent PNG pixel oluştur (cache edilmiş)"""
    img = Image.new('RGBA', (1, 1), (0, 0, 0, 0))
    img_io = io.BytesIO()
    img.save(img_io, 'PNG', optimize=True)
    return img_io.getvalue()


def create_mini_logo() -> bytes:
    """
    16x16 mini tracking logo oluştur
    
    Mail clientların "görseller yüklensin mi?" diye sormaması için
    küçük ama görünür bir logo döndürür.
    
    Logo: Basit mavi nokta (B2B marka rengi)
    """
    try:
        # 16x16 boyutunda transparent background
        img = Image.new('RGBA', (16, 16), (0, 0, 0, 0))
        
        # Mavi nokta çiz (B2B marka rengi: #0d7377)
        from PIL import ImageDraw
        draw = ImageDraw.Draw(img)
        
        # Merkeze mavi daire çiz (görünür ama ince)
        # Renk: RGB(13, 115, 119) - B2B Mavi
        # Alpha: 180 (orta şeffaflık - mail'de görünür)
        circle_color = (13, 115, 119, 180)
        
        # 16x16'lık alanda 12x12 daire (2px margin)
        draw.ellipse([2, 2, 14, 14], fill=circle_color)
        
        # PNG olarak kaydet
        img_io = io.BytesIO()
        img.save(img_io, 'PNG', optimize=True)
        return img_io.getvalue()
        
    except Exception as e:
        logger.error(f"Mini logo oluşturma hatası: {e}")
        # Hata olursa transparent pixel döndür
        return create_transparent_pixel()


# Cache'ler (her seferinde oluşturmamak için)
PIXEL_CACHE = create_transparent_pixel()
LOGO_CACHE = create_mini_logo()


def extract_client_info(request: Request) -> Dict:
    """İstek bilgilerini çıkar (IP, User-Agent, Browser, OS vb.)"""
    # IP adresi
    ip_address = request.headers.get("X-Forwarded-For")
    if ip_address:
        ip_address = ip_address.split(",")[0].strip()
    else:
        ip_address = request.client.host if request.client else "unknown"
    
    # User-Agent parse
    user_agent_string = request.headers.get("User-Agent", "")
    user_agent = parse_user_agent(user_agent_string)
    
    return {
        'ip_address': ip_address,
        'user_agent': user_agent_string,
        'device_type': 'Mobile' if user_agent.is_mobile else ('Tablet' if user_agent.is_tablet else 'Desktop'),
        'browser': f"{user_agent.browser.family} {user_agent.browser.version_string}",
        'os': f"{user_agent.os.family} {user_agent.os.version_string}",
        'referer': request.headers.get("Referer"),
    }


async def notify_main_api(endpoint: str, data: Dict, method: str = 'POST'):
    """
    Ana API'ye asenkron bildirim gönder
    
    NOT: Ana API opsiyonel - bağlantı hatası tracking'i durdurmaz
    """
    try:
        url = f"{MAIN_API_URL}{endpoint}"
        headers = {
            'Content-Type': 'application/json',
            'X-API-Key': API_KEY
        }
        
        # Asyncio ile HTTP request
        loop = asyncio.get_event_loop()
        
        if method.upper() == 'POST':
            response = await loop.run_in_executor(
                None,
                lambda: requests.post(url, json=data, headers=headers, timeout=3)
            )
        elif method.upper() == 'GET':
            response = await loop.run_in_executor(
                None,
                lambda: requests.get(url, headers=headers, timeout=3)
            )
        else:
            logger.debug(f"Desteklenmeyen HTTP metodu: {method}")
            return False
        
        if response.status_code in [200, 201]:
            logger.debug(f"✅ Ana API bildirimi başarılı: {endpoint}")
            return True
        else:
            logger.debug(f"⚠️ Ana API hatası: {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        # Sessizce hata logla - Ana API kapalı olabilir, bu normal
        logger.debug(f"Ana API bağlantı hatası (normal): {MAIN_API_URL}")
        return False
    except Exception as e:
        logger.debug(f"Ana API bildirimi hatası: {e}")
        return False


# ==================== RATE LIMITING ====================

async def check_rate_limit(request: Request, endpoint: str) -> bool:
    """Rate limit kontrolü (IP bazlı)"""
    client_info = extract_client_info(request)
    ip_address = client_info['ip_address']
    
    # Database'den kontrol et
    allowed, remaining = db.check_rate_limit(ip_address, endpoint, limit=100, window_minutes=60)
    
    if not allowed:
        logger.warning(f"🚫 Rate limit aşıldı: {ip_address} - {endpoint}")
        raise HTTPException(
            status_code=429,
            detail="Too many requests. Please try again later."
        )
    
    logger.debug(f"✅ Rate limit OK: {ip_address} - Kalan: {remaining}")
    return True


# ==================== API ENDPOINTS ====================

@app.get("/")
async def root():
    """Ana sayfa"""
    return {
            "service": "B2B Tracking Pixel Server",
            "version": "2.0.0",
            "mode": "Windows PC",
            "status": "running",
            "features": [
                "Email open tracking (1x1 pixel)",
                "Link click tracking",
                "Unsubscribe management",
                "Real-time analytics",
                "Rate limiting",
                "Async processing"
            ]
    }


@app.get("/api/health")
async def health_check():
    """Sunucu sağlık kontrolü"""
    try:
        # Database bağlantı testi
        stats = db.get_overall_stats()
        
        # NOT: Ana API kontrolü kaldırıldı - sürekli error loglarını önlemek için
        # Tracking server bağımsız çalışabilir, ana API optional
        
        import os
        is_railway = os.getenv('RAILWAY_ENVIRONMENT') is not None
        
        return {
            'status': 'healthy',
            'service': 'Tracking Pixel Server',
            'version': '2.0.0',
            'timestamp': datetime.now().isoformat(),
            'database': 'connected',
            'total_emails_tracked': stats.get('total_sent', 0),
            'mode': 'railway_cloud' if is_railway else 'windows_pc',
            'deployment': 'Railway.app' if is_railway else 'Local'
        }
    except Exception as e:
        logger.error(f"Health check hatası: {e}")
        return {
            'status': 'unhealthy',
            'error': str(e)
        }


@app.post("/api/tracking/register")
async def register_email(email_data: EmailRegistration, background_tasks: BackgroundTasks):
    """
    Email gönderim kaydı
    EmailManager tarafından çağrılır
    """
    logger.info("=" * 80)
    logger.info("📨 YENİ EMAIL KAYIT TALEBİ GELDİ!")
    logger.info("=" * 80)
    logger.info(f"   Tracking ID: {email_data.tracking_id}")
    logger.info(f"   Firm ID: {email_data.firm_id}")
    logger.info(f"   Alıcı: {email_data.to_email}")
    logger.info(f"   Konu: {email_data.subject[:50]}...")
    
    try:
        # Database'e kaydet
        logger.info(f"\n📍 Database'e kaydediliyor...")
        success = db.register_email(
            tracking_id=email_data.tracking_id,
            firm_id=email_data.firm_id,
            to_email=email_data.to_email,
            subject=email_data.subject,
            body=email_data.body
        )
        
        if success:
            logger.info(f"   ✅ Database kaydı BAŞARILI!")
        else:
            logger.error(f"   ❌ Database kaydı BAŞARISIZ!")
        
        if not success:
            logger.error(f"   ❌ HATA: Email kaydedilemedi!")
            raise HTTPException(status_code=500, detail="Email kaydedilemedi")
        
        # Ana API'ye bildirim (opsiyonel - background task)
        background_tasks.add_task(
            notify_main_api,
            '/api/tracking/register',
            {
                'tracking_id': email_data.tracking_id,
                'firm_id': email_data.firm_id,
                'to_email': email_data.to_email,
                'subject': email_data.subject,
                'sent_at': email_data.sent_at or datetime.now().isoformat()
            }
        )
        
        logger.info(f"\n✅ EMAIL KAYDI TAMAMLANDI!")
        logger.info(f"   Tracking ID: {email_data.tracking_id}")
        logger.info("=" * 80)
        
        return {
            'status': 'success',
            'tracking_id': email_data.tracking_id,
            'message': 'Email registered successfully'
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Email kayıt hatası: {e}")
        logger.error(f"   Hata detayı: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        
        # JSON formatında hata döndür (HTML değil!)
        return JSONResponse(
            status_code=500,
            content={
                'status': 'error',
                'error': str(e),
                'message': 'Email kaydedilemedi'
            }
        )


@app.get("/track/{tracking_id}.png")
async def track_email_open(
    tracking_id: str,
    request: Request,
    background_tasks: BackgroundTasks
):
    """
    Email açılma tracking pixel
    Email açıldığında bu endpoint çağrılır
    
    NOT: ibrahimcete@trsatis.com adresine gönderilen maillerin açılması tracking'e kaydedilmez
    (Gönderen kişinin kendi kontrolü için açması sayılmaz)
    """
    logger.info("=" * 80)
    logger.info("📧 PIXEL İSTEĞİ GELDİ!")
    logger.info("=" * 80)
    logger.info(f"   Tracking ID: {tracking_id}")
    logger.info(f"   IP: {request.client.host if request.client else 'unknown'}")
    logger.info(f"   User-Agent: {request.headers.get('User-Agent', 'unknown')[:50]}...")
    
    try:
        # Rate limit kontrolü
        logger.info(f"\n📍 ADIM 1: Rate limit kontrolü yapılıyor...")
        await check_rate_limit(request, f"/track/{tracking_id}")
        
        # İstek bilgilerini çıkar
        logger.info(f"\n📍 ADIM 2: Client bilgileri çıkarılıyor...")
        client_info = extract_client_info(request)
        logger.info(f"   IP: {client_info['ip_address']}")
        logger.info(f"   Device: {client_info['device_type']}")
        logger.info(f"   Browser: {client_info['browser']}")
        
        # FİLTRE: Bu mail'i kimin açtığını kontrol et
        # Email tracking bilgilerini al
        logger.info(f"\n📍 ADIM 3: Database'den email bilgileri alınıyor...")
        logger.info(f"   Tracking ID: {tracking_id}")
        email_stats = db.get_email_stats(tracking_id)
        
        if email_stats:
            logger.info(f"   ✅ Email bulundu!")
            logger.info(f"   Alıcı: {email_stats.get('to_email', 'N/A')}")
            logger.info(f"   Konu: {email_stats.get('subject', 'N/A')[:50]}...")
            logger.info(f"   Gönderim: {email_stats.get('sent_at', 'N/A')}")
        else:
            logger.warning(f"   ⚠️ Email bulunamadı! Tracking ID database'de yok: {tracking_id}")
        
        if email_stats:
            to_email = email_stats.get('to_email', '').lower()
            
            logger.info(f"\n📍 ADIM 4: Email sahibi kontrolü")
            logger.info(f"   Alıcı email: {to_email}")
            
            # Eğer gönderen kişinin kendi maili ise tracking kaydetme
            if to_email == 'ibrahimcete@trsatis.com':
                logger.info(f"   🔇 KENDİ MAİLİNİZ - Tracking kaydedilmeyecek!")
                logger.info(f"   Sebep: Kendi kontrolünüz için açmanız gerçek müşteri açılması değil")
                # Pixel döndür ama kayıt yapma
                return Response(
                    content=PIXEL_CACHE,
                    media_type="image/png",
                    headers={
                        "Cache-Control": "no-cache, no-store, must-revalidate",
                        "Pragma": "no-cache",
                        "Expires": "0"
                    }
                )
        
        # Müşteri maili - Normal tracking kaydı yap
        logger.info(f"\n📍 ADIM 5: MÜŞTERİ MAİLİ - Tracking kaydediliyor!")
        logger.info(f"   Tracking ID: {tracking_id}")
        logger.info(f"   IP: {client_info.get('ip_address')}")
        logger.info(f"   Device: {client_info.get('device_type')}")
        logger.info(f"   Browser: {client_info.get('browser')}")
        
        # Database'e kaydet (background task)
        logger.info(f"\n📍 ADIM 6: Database'e kayıt yapılıyor...")
        try:
            # Direkt kaydet (background task değil - hata görmek için)
            success = db.record_open(
                tracking_id,
                client_info.get('ip_address'),
                client_info.get('user_agent'),
                device_type=client_info.get('device_type'),
                browser=client_info.get('browser'),
                os=client_info.get('os')
            )
            
            if success:
                logger.info(f"   ✅ Database kaydı BAŞARILI!")
            else:
                logger.error(f"   ❌ Database kaydı BAŞARISIZ!")
        except Exception as e:
            logger.error(f"   ❌ Database kayıt hatası: {e}")
            import traceback
            logger.error(traceback.format_exc())
        
        # Ana API'ye bildirim (opsiyonel - background task)
        background_tasks.add_task(
            notify_main_api,
            '/api/tracking/sync',
            {
                'opens': [{
                    'tracking_id': tracking_id,
                    'opened_at': datetime.now().isoformat(),
                    'ip_address': client_info['ip_address'],
                    'user_agent': client_info['user_agent'],
                    'device_type': client_info['device_type']
                }]
            }
        )
        
        logger.info(f"\n✅ TRACKING TAMAMLANDI!")
        logger.info(f"   Tracking ID: {tracking_id}")
        logger.info(f"   Device: {client_info['device_type']}")
        logger.info("=" * 80)
        
        # 1x1 Transparent pixel döndür (standart tracking)
        return Response(
            content=PIXEL_CACHE,
            media_type="image/png",
            headers={
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0"
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Tracking pixel hatası: {e}")
        # Hata olsa bile pixel döndür
        return Response(content=PIXEL_CACHE, media_type="image/png")


@app.get("/click/{tracking_id}")
async def track_link_click(
    tracking_id: str,
    url: str,
    request: Request,
    background_tasks: BackgroundTasks
):
    """
    Link tıklama tracking
    Email içindeki linkler tıklandığında bu endpoint çağrılır
    """
    try:
        # Rate limit kontrolü
        await check_rate_limit(request, f"/click/{tracking_id}")
        
        # İstek bilgilerini çıkar
        client_info = extract_client_info(request)
        
        # Database'e kaydet (background task)
        background_tasks.add_task(
            db.record_click,
            tracking_id,
            url,
            client_info['ip_address'],
            client_info['user_agent']
        )
        
        # Ana API'ye bildirim (background task)
        background_tasks.add_task(
            notify_main_api,
            '/api/tracking/sync-clicks',
            {
                'clicks': [{
                    'tracking_id': tracking_id,
                    'clicked_at': datetime.now().isoformat(),
                    'link_url': url,
                    'ip_address': client_info['ip_address'],
                    'user_agent': client_info['user_agent']
                }]
            }
        )
        
        logger.info(f"🖱️ Link tıklandı: {tracking_id} → {url[:50]}")
        
        # Kullanıcıyı hedef URL'e yönlendir
        return RedirectResponse(url=url, status_code=302)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Link tracking hatası: {e}")
        # Hata olsa bile yönlendir
        return RedirectResponse(url=url, status_code=302)


@app.get("/unsubscribe/{firm_id}/{email_hash}")
async def unsubscribe_page(
    firm_id: str,
    email_hash: str,
    request: Request,
    background_tasks: BackgroundTasks
):
    """Abonelikten çıkma sayfası"""
    try:
        # İstek bilgilerini çıkar
        client_info = extract_client_info(request)
        
        # Email hash'inden tracking_id bul (basitleştirilmiş)
        tracking_id = f"{firm_id}-{email_hash}"
        
        # Database'den email bilgilerini al
        email_stats = db.get_email_stats(tracking_id)
        email_address = email_stats['to_email'] if email_stats else 'unknown'
        
        # Unsubscribe işle (background task)
        background_tasks.add_task(
            db.record_unsubscribe,
            email_address,
            firm_id,
            tracking_id,
            "User request via unsubscribe link",
            client_info['ip_address'],
            client_info['user_agent']
        )
        
        # Ana API'ye bildirim (background task)
        background_tasks.add_task(
            notify_main_api,
            '/api/tracking/unsubscribe',
            {
                'firm_id': firm_id,
                'email': email_address,
                'reason': 'User request via unsubscribe link'
            }
        )
        
        logger.info(f"🚫 Abonelikten çıkıldı: {email_address}")
        
        # Başarı sayfası
        html_content = """
        <!DOCTYPE html>
        <html lang="tr">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Abonelikten Çıkıldı</title>
            <style>
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    min-height: 100vh;
                    margin: 0;
                    padding: 20px;
                }
                .container {
                    background: white;
                    padding: 40px;
                    border-radius: 20px;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                    text-align: center;
                    max-width: 500px;
                    width: 100%;
                }
                .icon {
                    font-size: 64px;
                    margin-bottom: 20px;
                }
                h1 {
                    color: #28a745;
                    margin: 0 0 10px 0;
                }
                p {
                    color: #666;
                    font-size: 16px;
                    line-height: 1.6;
                }
                .info {
                    background: #f8f9fa;
                    padding: 15px;
                    border-radius: 10px;
                    margin-top: 20px;
                    font-size: 14px;
                    color: #495057;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="icon">✓</div>
                <h1>Abonelikten Çıkıldı</h1>
                <p>Email listemizden başarıyla çıkarıldınız.</p>
                <p>Size daha fazla email göndermeyeceğiz.</p>
                <div class="info">
                    Eğer bu bir hata ise veya tekrar abone olmak isterseniz,
                    lütfen bizimle iletişime geçin.
                </div>
            </div>
        </body>
        </html>
        """
        
        return HTMLResponse(content=html_content)
        
    except Exception as e:
        logger.error(f"Unsubscribe hatası: {e}")
        return HTMLResponse(
            content="<h1>Hata</h1><p>Bir sorun oluştu. Lütfen daha sonra tekrar deneyin.</p>",
            status_code=500
        )


@app.get("/api/tracking/statistics")
async def get_tracking_statistics(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None
):
    """Tracking istatistiklerini getir"""
    try:
        # Tarih parametrelerini parse et
        start_dt = datetime.fromisoformat(start_date) if start_date else None
        end_dt = datetime.fromisoformat(end_date) if end_date else None
        
        # İstatistikleri al
        stats = db.get_overall_stats(start_date=start_dt, end_date=end_dt)
        stats['generated_at'] = datetime.now().isoformat()
        
        return stats
        
    except Exception as e:
        logger.error(f"İstatistik hatası: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/tracking/{tracking_id}")
async def get_tracking_details(tracking_id: str):
    """Belirli bir email'in tracking detaylarını getir"""
    try:
        stats = db.get_email_stats(tracking_id)
        
        if not stats:
            raise HTTPException(status_code=404, detail="Tracking ID bulunamadı")
        
        return stats
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Tracking detay hatası: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/tracking/firm/{firm_id}")
async def get_firm_tracking(firm_id: str):
    """Firma bazlı tracking istatistikleri"""
    try:
        stats = db.get_firm_stats(firm_id)
        
        if not stats:
            raise HTTPException(status_code=404, detail="Firma bulunamadı")
        
        return stats
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Firma tracking hatası: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/tracking/top-performers")
async def get_top_performers(limit: int = 10):
    """En yüksek engagement skorlu emailler"""
    try:
        top = db.get_top_performers(limit=limit)
        
        return {
            'top_performers': top,
            'count': len(top),
            'generated_at': datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Top performers hatası: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/admin/cleanup")
async def cleanup_old_records(days: int = 90):
    """Eski kayıtları temizle (admin endpoint)"""
    try:
        success = db.cleanup_old_records(days=days)
        
        return {
            'status': 'success' if success else 'failed',
            'days': days,
            'message': f'{days} günden eski kayıtlar temizlendi'
        }
        
    except Exception as e:
        logger.error(f"Cleanup hatası: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== ERROR HANDLERS ====================

@app.exception_handler(404)
async def not_found_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=404,
        content={
            'error': 'Not found',
            'message': 'The requested endpoint does not exist',
            'path': str(request.url)
        }
    )


@app.exception_handler(500)
async def internal_error_handler(request: Request, exc: Exception):
    logger.error(f"Internal server error: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            'error': 'Internal server error',
            'message': 'An unexpected error occurred'
        }
    )


# ==================== STARTUP & SHUTDOWN ====================
# Modern lifespan event handlers kullanılıyor (yukarıda tanımlı)


# ==================== MAIN ====================

if __name__ == "__main__":
    import os
    
    # Railway deployment kontrolü
    is_railway = os.getenv('RAILWAY_ENVIRONMENT') is not None
    port = int(os.getenv('PORT', 5000))
    host = "0.0.0.0" if is_railway else "127.0.0.1"
    
    print("=" * 80)
    print(f"📧 B2B TRACKING PIXEL SERVER - {'RAILWAY CLOUD' if is_railway else 'WINDOWS PC'} EDITION")
    print("=" * 80)
    print("🚀 Server başlatılıyor...")
    print(f"🌐 Host: {host}")
    print(f"🔌 Port: {port}")
    if not is_railway:
        print(f"📝 API Docs: http://localhost:{port}/docs")
        print(f"📊 Health Check: http://localhost:{port}/api/health")
    print("=" * 80)
    
    # Uvicorn ile başlat
    uvicorn.run(
        "tracking_pixel_server:app",
        host=host,
        port=port,
        reload=False,
        workers=1,
        log_level="info",
        access_log=True
    )

