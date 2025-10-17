#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tracking Pixel Database - Raspberry Pi Uyumlu
SQLite tabanlı hafif ve performanslı tracking veri yönetimi
"""

import sqlite3
import json
import logging
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from contextlib import contextmanager
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TrackingDatabase:
    """Tracking verileri için özel database yöneticisi"""
    
    def __init__(self, db_path: str = "tracking.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        self.conn = None
        self._init_database()
        logger.info(f"📊 Tracking Database başlatıldı: {db_path}")
    
    def _init_database(self):
        """Veritabanını başlat ve tabloları oluştur"""
        try:
            self.conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                timeout=30.0
            )
            self.conn.row_factory = sqlite3.Row
            
            # SQLite optimizasyonları (Raspberry Pi için)
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")
            self.conn.execute("PRAGMA temp_store=MEMORY")
            self.conn.execute("PRAGMA cache_size=5000")
            self.conn.execute("PRAGMA mmap_size=30000000000")
            
            self._create_tables()
            self._create_indexes()
            
        except Exception as e:
            logger.error(f"Database başlatma hatası: {e}")
            raise
    
    def _create_tables(self):
        """Tracking tabloları oluştur"""
        
        # 1. Email gönderim kayıtları
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS email_tracking (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tracking_id TEXT UNIQUE NOT NULL,
                firm_id TEXT NOT NULL,
                to_email TEXT NOT NULL,
                subject TEXT,
                body TEXT,
                sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                
                -- Açılma verileri
                opened INTEGER DEFAULT 0,
                first_opened_at TIMESTAMP,
                last_opened_at TIMESTAMP,
                open_count INTEGER DEFAULT 0,
                
                -- Tıklama verileri
                clicked INTEGER DEFAULT 0,
                first_clicked_at TIMESTAMP,
                last_clicked_at TIMESTAMP,
                click_count INTEGER DEFAULT 0,
                
                -- Metadata
                user_agent TEXT,
                ip_address TEXT,
                device_type TEXT,
                browser TEXT,
                os TEXT,
                location TEXT,
                
                -- Durum
                status TEXT DEFAULT 'sent',
                unsubscribed INTEGER DEFAULT 0,
                unsubscribed_at TIMESTAMP,
                bounced INTEGER DEFAULT 0,
                bounced_at TIMESTAMP,
                
                -- İstatistikler
                engagement_score REAL DEFAULT 0.0,
                
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # 2. Pixel açılma logları (detaylı)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS pixel_opens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tracking_id TEXT NOT NULL,
                opened_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                user_agent TEXT,
                referer TEXT,
                device_type TEXT,
                browser TEXT,
                os TEXT,
                location TEXT,
                
                FOREIGN KEY (tracking_id) REFERENCES email_tracking(tracking_id)
            )
        """)
        
        # 3. Link tıklama logları (detaylı)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS link_clicks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tracking_id TEXT NOT NULL,
                link_url TEXT NOT NULL,
                clicked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                user_agent TEXT,
                referer TEXT,
                device_type TEXT,
                browser TEXT,
                os TEXT,
                location TEXT,
                
                FOREIGN KEY (tracking_id) REFERENCES email_tracking(tracking_id)
            )
        """)
        
        # 4. Abonelikten çıkma kayıtları
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS unsubscribes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                firm_id TEXT,
                tracking_id TEXT,
                reason TEXT,
                unsubscribed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                user_agent TEXT
            )
        """)
        
        # 5. Bounce kayıtları
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS bounces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tracking_id TEXT NOT NULL,
                email TEXT NOT NULL,
                bounce_type TEXT,
                bounce_reason TEXT,
                bounced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                
                FOREIGN KEY (tracking_id) REFERENCES email_tracking(tracking_id)
            )
        """)
        
        # 6. Rate limiting tablosu (IP bazlı)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS rate_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                request_count INTEGER DEFAULT 1,
                window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_request TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                blocked INTEGER DEFAULT 0,
                
                UNIQUE(ip_address, endpoint, window_start)
            )
        """)
        
        # 7. Kampanya istatistikleri (toplu mail gönderimler)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS campaigns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_name TEXT NOT NULL,
                campaign_type TEXT,
                description TEXT,
                
                -- İstatistikler
                total_sent INTEGER DEFAULT 0,
                total_opened INTEGER DEFAULT 0,
                total_clicked INTEGER DEFAULT 0,
                total_unsubscribed INTEGER DEFAULT 0,
                total_bounced INTEGER DEFAULT 0,
                
                -- Oranlar
                open_rate REAL DEFAULT 0.0,
                click_rate REAL DEFAULT 0.0,
                ctr REAL DEFAULT 0.0,
                unsubscribe_rate REAL DEFAULT 0.0,
                bounce_rate REAL DEFAULT 0.0,
                
                -- Tarihler
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # 8. Server performans metrikleri
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS server_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                metric_type TEXT NOT NULL,
                metric_value REAL,
                metadata TEXT,
                recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        self.conn.commit()
        logger.info("✅ Tracking tabloları oluşturuldu")
    
    def _create_indexes(self):
        """Performans için indexler oluştur"""
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_tracking_id ON email_tracking(tracking_id)",
            "CREATE INDEX IF NOT EXISTS idx_firm_id ON email_tracking(firm_id)",
            "CREATE INDEX IF NOT EXISTS idx_to_email ON email_tracking(to_email)",
            "CREATE INDEX IF NOT EXISTS idx_sent_at ON email_tracking(sent_at)",
            "CREATE INDEX IF NOT EXISTS idx_opened ON email_tracking(opened)",
            "CREATE INDEX IF NOT EXISTS idx_clicked ON email_tracking(clicked)",
            
            "CREATE INDEX IF NOT EXISTS idx_pixel_tracking_id ON pixel_opens(tracking_id)",
            "CREATE INDEX IF NOT EXISTS idx_pixel_opened_at ON pixel_opens(opened_at)",
            
            "CREATE INDEX IF NOT EXISTS idx_click_tracking_id ON link_clicks(tracking_id)",
            "CREATE INDEX IF NOT EXISTS idx_click_clicked_at ON link_clicks(clicked_at)",
            
            "CREATE INDEX IF NOT EXISTS idx_unsub_email ON unsubscribes(email)",
            "CREATE INDEX IF NOT EXISTS idx_rate_ip_endpoint ON rate_limits(ip_address, endpoint)",
        ]
        
        for index_sql in indexes:
            try:
                self.conn.execute(index_sql)
            except sqlite3.OperationalError:
                pass  # Index zaten var
        
        self.conn.commit()
        logger.info("✅ Indexler oluşturuldu")
    
    @contextmanager
    def get_cursor(self):
        """Thread-safe cursor"""
        with self.lock:
            cursor = self.conn.cursor()
            try:
                yield cursor
                self.conn.commit()
            except Exception as e:
                self.conn.rollback()
                logger.error(f"Database işlem hatası: {e}")
                raise
            finally:
                cursor.close()
    
    # ==================== EMAIL TRACKING ====================
    
    def register_email(self, tracking_id: str, firm_id: str, to_email: str,
                      subject: str, body: str) -> bool:
        """Email gönderim kaydı oluştur"""
        try:
            with self.get_cursor() as cursor:
                cursor.execute("""
                    INSERT OR REPLACE INTO email_tracking
                    (tracking_id, firm_id, to_email, subject, body, sent_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (tracking_id, firm_id, to_email, subject, body, datetime.now()))
            
            logger.info(f"📧 Email kaydedildi: {tracking_id}")
            return True
            
        except Exception as e:
            logger.error(f"Email kayıt hatası: {e}")
            return False
    
    def record_open(self, tracking_id: str, ip_address: str = None,
                   user_agent: str = None, **metadata) -> bool:
        """Email açılma kaydı"""
        try:
            with self.get_cursor() as cursor:
                now = datetime.now()
                
                # Email tracking güncelle
                cursor.execute("""
                    UPDATE email_tracking
                    SET opened = 1,
                        open_count = open_count + 1,
                        first_opened_at = COALESCE(first_opened_at, ?),
                        last_opened_at = ?,
                        ip_address = ?,
                        user_agent = ?,
                        device_type = ?,
                        browser = ?,
                        os = ?,
                        updated_at = ?
                    WHERE tracking_id = ?
                """, (
                    now, now,
                    ip_address,
                    user_agent,
                    metadata.get('device_type'),
                    metadata.get('browser'),
                    metadata.get('os'),
                    now,
                    tracking_id
                ))
                
                # Güncelleme kontrolü
                if cursor.rowcount == 0:
                    logger.warning(f"⚠️ Email tracking güncellenemedi: {tracking_id}")
                else:
                    logger.info(f"✅ Email tracking güncellendi: {tracking_id}")
                
                # Detaylı açılma logu
                cursor.execute("""
                    INSERT INTO pixel_opens
                    (tracking_id, ip_address, user_agent, referer,
                     device_type, browser, os, location)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    tracking_id,
                    ip_address,
                    user_agent,
                    metadata.get('referer'),
                    metadata.get('device_type'),
                    metadata.get('browser'),
                    metadata.get('os'),
                    metadata.get('location')
                ))
                
                # Engagement score güncelle
                self._update_engagement_score(cursor, tracking_id)
            
            logger.info(f"👀 Email açıldı: {tracking_id}")
            return True
            
        except Exception as e:
            logger.error(f"Açılma kayıt hatası: {e}")
            return False
    
    def record_click(self, tracking_id: str, link_url: str,
                    ip_address: str = None, user_agent: str = None,
                    **metadata) -> bool:
        """Link tıklama kaydı"""
        try:
            with self.get_cursor() as cursor:
                now = datetime.now()
                
                # Email tracking güncelle
                cursor.execute("""
                    UPDATE email_tracking
                    SET clicked = 1,
                        click_count = click_count + 1,
                        first_clicked_at = COALESCE(first_clicked_at, ?),
                        last_clicked_at = ?,
                        updated_at = ?
                    WHERE tracking_id = ?
                """, (now, now, now, tracking_id))
                
                # Detaylı tıklama logu
                cursor.execute("""
                    INSERT INTO link_clicks
                    (tracking_id, link_url, ip_address, user_agent, referer,
                     device_type, browser, os, location)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    tracking_id,
                    link_url,
                    ip_address,
                    user_agent,
                    metadata.get('referer'),
                    metadata.get('device_type'),
                    metadata.get('browser'),
                    metadata.get('os'),
                    metadata.get('location')
                ))
                
                # Engagement score güncelle
                self._update_engagement_score(cursor, tracking_id)
            
            logger.info(f"🖱️ Link tıklandı: {tracking_id} -> {link_url[:50]}")
            return True
            
        except Exception as e:
            logger.error(f"Tıklama kayıt hatası: {e}")
            return False
    
    def record_unsubscribe(self, email: str, firm_id: str = None,
                          tracking_id: str = None, reason: str = None,
                          ip_address: str = None, user_agent: str = None) -> bool:
        """Abonelikten çıkma kaydı"""
        try:
            with self.get_cursor() as cursor:
                # Unsubscribe kaydı
                cursor.execute("""
                    INSERT INTO unsubscribes
                    (email, firm_id, tracking_id, reason, ip_address, user_agent)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (email, firm_id, tracking_id, reason, ip_address, user_agent))
                
                # Email tracking güncelle
                if tracking_id:
                    cursor.execute("""
                        UPDATE email_tracking
                        SET unsubscribed = 1,
                            unsubscribed_at = ?,
                            updated_at = ?
                        WHERE tracking_id = ?
                    """, (datetime.now(), datetime.now(), tracking_id))
            
            logger.info(f"🚫 Abonelikten çıkıldı: {email}")
            return True
            
        except Exception as e:
            logger.error(f"Unsubscribe kayıt hatası: {e}")
            return False
    
    def _update_engagement_score(self, cursor, tracking_id: str):
        """Engagement score hesapla ve güncelle"""
        try:
            # Puanlama: Açılma=30, Tıklama=50, Tekrar açılma/tıklama=10
            cursor.execute("""
                SELECT opened, open_count, clicked, click_count
                FROM email_tracking
                WHERE tracking_id = ?
            """, (tracking_id,))
            
            row = cursor.fetchone()
            if not row:
                return
            
            opened, open_count, clicked, click_count = row
            
            score = 0
            if opened:
                score += 30
                if open_count > 1:
                    score += min((open_count - 1) * 5, 20)  # Max +20
            
            if clicked:
                score += 50
                if click_count > 1:
                    score += min((click_count - 1) * 10, 30)  # Max +30
            
            score = min(score, 100)  # Max 100
            
            cursor.execute("""
                UPDATE email_tracking
                SET engagement_score = ?
                WHERE tracking_id = ?
            """, (score, tracking_id))
            
        except Exception as e:
            logger.error(f"Engagement score güncelleme hatası: {e}")
    
    # ==================== ANALYTICS ====================
    
    def get_email_stats(self, tracking_id: str) -> Optional[Dict]:
        """Belirli bir email'in istatistikleri"""
        try:
            with self.get_cursor() as cursor:
                cursor.execute("""
                    SELECT *
                    FROM email_tracking
                    WHERE tracking_id = ?
                """, (tracking_id,))
                
                row = cursor.fetchone()
                if not row:
                    return None
                
                return dict(row)
                
        except Exception as e:
            logger.error(f"Email stats hatası: {e}")
            return None
    
    def get_overall_stats(self, start_date: datetime = None,
                         end_date: datetime = None) -> Dict:
        """Genel istatistikler"""
        try:
            with self.get_cursor() as cursor:
                where_clause = ""
                params = []
                
                if start_date:
                    where_clause += " AND sent_at >= ?"
                    params.append(start_date)
                
                if end_date:
                    where_clause += " AND sent_at <= ?"
                    params.append(end_date)
                
                cursor.execute(f"""
                    SELECT
                        COUNT(*) as total_sent,
                        SUM(CASE WHEN opened = 1 THEN 1 ELSE 0 END) as total_opened,
                        SUM(CASE WHEN clicked = 1 THEN 1 ELSE 0 END) as total_clicked,
                        SUM(open_count) as total_opens,
                        SUM(click_count) as total_clicks,
                        SUM(CASE WHEN unsubscribed = 1 THEN 1 ELSE 0 END) as total_unsubscribed,
                        SUM(CASE WHEN bounced = 1 THEN 1 ELSE 0 END) as total_bounced,
                        AVG(engagement_score) as avg_engagement
                    FROM email_tracking
                    WHERE 1=1 {where_clause}
                """, params)
                
                row = cursor.fetchone()
                
                total_sent = row['total_sent'] or 0
                total_opened = row['total_opened'] or 0
                total_clicked = row['total_clicked'] or 0
                
                return {
                    'total_sent': total_sent,
                    'total_opened': total_opened,
                    'total_clicked': total_clicked,
                    'total_opens': row['total_opens'] or 0,
                    'total_clicks': row['total_clicks'] or 0,
                    'total_unsubscribed': row['total_unsubscribed'] or 0,
                    'total_bounced': row['total_bounced'] or 0,
                    'avg_engagement': round(row['avg_engagement'] or 0, 2),
                    
                    # Oranlar
                    'open_rate': round((total_opened / total_sent * 100) if total_sent > 0 else 0, 2),
                    'click_rate': round((total_clicked / total_sent * 100) if total_sent > 0 else 0, 2),
                    'ctr': round((total_clicked / total_opened * 100) if total_opened > 0 else 0, 2),
                }
                
        except Exception as e:
            logger.error(f"Overall stats hatası: {e}")
            return {}
    
    def get_top_performers(self, limit: int = 10) -> List[Dict]:
        """En yüksek engagement skorlu emailler"""
        try:
            with self.get_cursor() as cursor:
                cursor.execute("""
                    SELECT tracking_id, to_email, subject,
                           open_count, click_count, engagement_score,
                           sent_at
                    FROM email_tracking
                    WHERE engagement_score > 0
                    ORDER BY engagement_score DESC
                    LIMIT ?
                """, (limit,))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            logger.error(f"Top performers hatası: {e}")
            return []
    
    def get_firm_stats(self, firm_id: str) -> Dict:
        """Firma bazlı istatistikler"""
        try:
            with self.get_cursor() as cursor:
                cursor.execute("""
                    SELECT
                        COUNT(*) as total_sent,
                        SUM(CASE WHEN opened = 1 THEN 1 ELSE 0 END) as total_opened,
                        SUM(CASE WHEN clicked = 1 THEN 1 ELSE 0 END) as total_clicked,
                        AVG(engagement_score) as avg_engagement,
                        MAX(sent_at) as last_sent
                    FROM email_tracking
                    WHERE firm_id = ?
                """, (firm_id,))
                
                row = cursor.fetchone()
                
                total_sent = row['total_sent'] or 0
                total_opened = row['total_opened'] or 0
                
                return {
                    'firm_id': firm_id,
                    'total_sent': total_sent,
                    'total_opened': total_opened,
                    'total_clicked': row['total_clicked'] or 0,
                    'avg_engagement': round(row['avg_engagement'] or 0, 2),
                    'last_sent': row['last_sent'],
                    'open_rate': round((total_opened / total_sent * 100) if total_sent > 0 else 0, 2),
                }
                
        except Exception as e:
            logger.error(f"Firm stats hatası: {e}")
            return {}
    
    # ==================== RATE LIMITING ====================
    
    def check_rate_limit(self, ip_address: str, endpoint: str,
                        limit: int = 100, window_minutes: int = 60) -> Tuple[bool, int]:
        """
        Rate limit kontrolü
        Returns: (allowed: bool, remaining_requests: int)
        """
        try:
            with self.get_cursor() as cursor:
                now = datetime.now()
                window_start = now - timedelta(minutes=window_minutes)
                
                # Mevcut kaydı bul veya oluştur
                cursor.execute("""
                    SELECT request_count, blocked
                    FROM rate_limits
                    WHERE ip_address = ? AND endpoint = ?
                      AND window_start >= ?
                    ORDER BY window_start DESC
                    LIMIT 1
                """, (ip_address, endpoint, window_start))
                
                row = cursor.fetchone()
                
                if not row:
                    # Yeni kayıt
                    cursor.execute("""
                        INSERT INTO rate_limits
                        (ip_address, endpoint, request_count, window_start)
                        VALUES (?, ?, 1, ?)
                    """, (ip_address, endpoint, now))
                    return True, limit - 1
                
                request_count = row['request_count']
                blocked = row['blocked']
                
                if blocked or request_count >= limit:
                    return False, 0
                
                # Sayaç artır
                cursor.execute("""
                    UPDATE rate_limits
                    SET request_count = request_count + 1,
                        last_request = ?
                    WHERE ip_address = ? AND endpoint = ?
                      AND window_start >= ?
                """, (now, ip_address, endpoint, window_start))
                
                return True, limit - request_count - 1
                
        except Exception as e:
            logger.error(f"Rate limit kontrol hatası: {e}")
            return True, limit  # Hata durumunda izin ver
    
    # ==================== CLEANUP ====================
    
    def cleanup_old_records(self, days: int = 90):
        """Eski kayıtları temizle"""
        try:
            with self.get_cursor() as cursor:
                cutoff_date = datetime.now() - timedelta(days=days)
                
                # Eski rate limit kayıtlarını sil
                cursor.execute("""
                    DELETE FROM rate_limits
                    WHERE window_start < ?
                """, (cutoff_date,))
                
                deleted_rate_limits = cursor.rowcount
                
                # Eski pixel/click loglarını sil (email tracking'i koru)
                cursor.execute("""
                    DELETE FROM pixel_opens
                    WHERE opened_at < ?
                """, (cutoff_date,))
                
                deleted_opens = cursor.rowcount
                
                cursor.execute("""
                    DELETE FROM link_clicks
                    WHERE clicked_at < ?
                """, (cutoff_date,))
                
                deleted_clicks = cursor.rowcount
                
                # VACUUM (disk alanı geri kazan)
                cursor.execute("VACUUM")
            
            logger.info(f"🧹 Cleanup tamamlandı: {deleted_rate_limits} rate_limits, "
                       f"{deleted_opens} opens, {deleted_clicks} clicks silindi")
            return True
            
        except Exception as e:
            logger.error(f"Cleanup hatası: {e}")
            return False
    
    def close(self):
        """Database bağlantısını kapat"""
        if self.conn:
            self.conn.close()
            logger.info("Database bağlantısı kapatıldı")


# ==================== TEST ====================

if __name__ == "__main__":
    print("=" * 70)
    print("📊 Tracking Database Test")
    print("=" * 70)
    
    # Test database
    db = TrackingDatabase("test_tracking.db")
    
    # Test email kaydı
    tracking_id = "test-firm-123-email-456"
    db.register_email(
        tracking_id=tracking_id,
        firm_id="test-firm-123",
        to_email="test@example.com",
        subject="Test Email",
        body="Test content"
    )
    
    # Test açılma
    db.record_open(
        tracking_id=tracking_id,
        ip_address="192.168.1.1",
        user_agent="Mozilla/5.0...",
        device_type="Desktop",
        browser="Chrome",
        os="Windows 10"
    )
    
    # Test tıklama
    db.record_click(
        tracking_id=tracking_id,
        link_url="https://example.com",
        ip_address="192.168.1.1",
        user_agent="Mozilla/5.0...",
        device_type="Desktop"
    )
    
    # İstatistikleri göster
    stats = db.get_overall_stats()
    print(f"\n📈 Genel İstatistikler:")
    print(f"  Gönderilen: {stats['total_sent']}")
    print(f"  Açılan: {stats['total_opened']} ({stats['open_rate']}%)")
    print(f"  Tıklanan: {stats['total_clicked']} ({stats['click_rate']}%)")
    print(f"  Ortalama Engagement: {stats['avg_engagement']}")
    
    # Email detayları
    email_stats = db.get_email_stats(tracking_id)
    print(f"\n📧 Email Detayları:")
    print(f"  Tracking ID: {email_stats['tracking_id']}")
    print(f"  Açılma sayısı: {email_stats['open_count']}")
    print(f"  Tıklama sayısı: {email_stats['click_count']}")
    print(f"  Engagement Score: {email_stats['engagement_score']}")
    
    # Rate limit testi
    allowed, remaining = db.check_rate_limit("192.168.1.1", "/track", limit=10)
    print(f"\n🚦 Rate Limit:")
    print(f"  İzinli: {allowed}")
    print(f"  Kalan: {remaining}")
    
    # Cleanup
    db.close()
    os.remove("test_tracking.db")
    
    print("\n✅ Test tamamlandı!")

