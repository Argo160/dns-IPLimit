#!/usr/bin/env python3
"""
AdGuard Home IP Limit Monitor - Improved Version
Detects concurrent usage and automatically bans violating IPs.
Optimized for handling 1000+ clients with memory management.
"""

import json
import time
import os
import sys
import signal
import logging
from collections import defaultdict, deque
from typing import Dict, Set, Tuple, Optional
import requests
from pathlib import Path

# ==============================================================================
# --- CONFIGURATION ---
# ==============================================================================

# Load configuration from environment variables with fallbacks
ADGUARD_LOG_FILE = os.getenv("ADGUARD_LOG_FILE", "/opt/AdGuardHome/data/querylog.json")
ADGUARD_URL = os.getenv("ADGUARD_URL", "http://127.0.0.1:3000")
ADGUARD_USERNAME = os.getenv("ADGUARD_USERNAME")
ADGUARD_PASSWORD = os.getenv("ADGUARD_PASSWORD")

# Detection & Ban Settings (configurable via environment)
TIME_WINDOW = int(os.getenv("TIME_WINDOW", "60"))  # seconds
BAN_DURATION = int(os.getenv("BAN_DURATION", "300"))  # seconds
MAX_CLIENTS_IN_MEMORY = int(os.getenv("MAX_CLIENTS_IN_MEMORY", "2000"))  # Memory limit
CLEANUP_INTERVAL = int(os.getenv("CLEANUP_INTERVAL", "300"))  # Clean inactive clients every 5 min
API_TIMEOUT = int(os.getenv("API_TIMEOUT", "5"))  # seconds
API_RETRY_DELAY = int(os.getenv("API_RETRY_DELAY", "10"))  # seconds between retries

# Logging configuration
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = os.getenv("LOG_FILE")  # Optional log file

# ==============================================================================
# --- SETUP LOGGING ---
# ==============================================================================

def setup_logging():
    """Configure logging with appropriate level and handlers."""
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL.upper()),
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            *([logging.FileHandler(LOG_FILE)] if LOG_FILE else [])
        ]
    )
    return logging.getLogger(__name__)

logger = setup_logging()

# ==============================================================================
# --- MEMORY-OPTIMIZED DATA STRUCTURES ---
# ==============================================================================

class MemoryOptimizedHistory:
    """Memory-efficient client history management with automatic cleanup."""
    
    def __init__(self, max_clients: int = MAX_CLIENTS_IN_MEMORY):
        self.client_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))  # Limit per client
        self.client_last_seen: Dict[str, float] = {}
        self.max_clients = max_clients
        self.last_cleanup = time.time()
    
    def add_entry(self, client_id: str, ip: str, timestamp: float):
        """Add a new entry for a client, with memory management."""
        self.client_history[client_id].append((timestamp, ip))
        self.client_last_seen[client_id] = timestamp
        
        # Periodic cleanup to prevent unbounded memory growth
        if len(self.client_history) > self.max_clients:
            self._cleanup_inactive_clients(timestamp)
    
    def get_history(self, client_id: str) -> deque:
        """Get history for a client."""
        return self.client_history[client_id]
    
    def clear_client(self, client_id: str):
        """Clear history for a specific client."""
        if client_id in self.client_history:
            del self.client_history[client_id]
        if client_id in self.client_last_seen:
            del self.client_last_seen[client_id]
    
    def _cleanup_inactive_clients(self, current_time: float):
        """Remove clients that haven't been seen in a while."""
        inactive_threshold = current_time - (TIME_WINDOW * 10)  # 10x time window
        clients_to_remove = [
            client_id for client_id, last_seen in self.client_last_seen.items()
            if last_seen < inactive_threshold
        ]
        
        removed_count = 0
        for client_id in clients_to_remove[:len(clients_to_remove)//2]:  # Remove half of inactive
            self.clear_client(client_id)
            removed_count += 1
        
        if removed_count > 0:
            logger.info(f"Memory cleanup: Removed {removed_count} inactive clients. "
                       f"Active clients: {len(self.client_history)}")
    
    def periodic_cleanup(self, current_time: float):
        """Perform regular maintenance cleanup."""
        if current_time - self.last_cleanup > CLEANUP_INTERVAL:
            self._cleanup_inactive_clients(current_time)
            self._cleanup_old_entries(current_time)
            self.last_cleanup = current_time
    
    def _cleanup_old_entries(self, current_time: float):
        """Remove old entries from all client histories."""
        cutoff_time = current_time - TIME_WINDOW
        for client_id, history in list(self.client_history.items()):
            # Remove old entries
            while history and history[0][0] < cutoff_time:
                history.popleft()
            
            # If history is empty, remove the client entirely
            if not history:
                self.clear_client(client_id)

# ==============================================================================
# --- MAIN MONITOR CLASS ---
# ==============================================================================

class AdGuardMonitor:
    """Main monitoring class with improved error handling and memory management."""
    
    def __init__(self):
        self.history = MemoryOptimizedHistory()
        self.banned_clients: Dict[str, float] = {}  # IP -> expiry_timestamp
        self.log_file_handle = None
        self.log_file_inode = None
        self.api_retry_count = 0
        self.running = True
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.running = False
        if self.log_file_handle:
            self.log_file_handle.close()
    
    def validate_configuration(self) -> bool:
        """Validate all configuration before starting."""
        errors = []
        
        # Check required credentials
        if not ADGUARD_USERNAME or not ADGUARD_PASSWORD:
            errors.append("ADGUARD_USERNAME and ADGUARD_PASSWORD must be set")
        
        # Check log file exists and is readable
        if not Path(ADGUARD_LOG_FILE).exists():
            errors.append(f"Log file not found: {ADGUARD_LOG_FILE}")
        elif not os.access(ADGUARD_LOG_FILE, os.R_OK):
            errors.append(f"Log file not readable: {ADGUARD_LOG_FILE}")
        
        # Validate numeric parameters
        if TIME_WINDOW < 1 or TIME_WINDOW > 3600:
            errors.append("TIME_WINDOW must be between 1 and 3600 seconds")
        
        if BAN_DURATION < 60:
            errors.append("BAN_DURATION must be at least 60 seconds")
        
        # Test API connectivity
        try:
            response = requests.get(
                f"{ADGUARD_URL}/control/status",
                auth=(ADGUARD_USERNAME, ADGUARD_PASSWORD),
                timeout=API_TIMEOUT
            )
            response.raise_for_status()
            logger.info("✓ AdGuard Home API connectivity confirmed")
        except requests.exceptions.RequestException as e:
            errors.append(f"Cannot connect to AdGuard Home API: {e}")
        
        if errors:
            for error in errors:
                logger.error(f"Configuration error: {error}")
            return False
        
        logger.info("✓ Configuration validation passed")
        return True
    
    def update_adguard_bans(self) -> bool:
        """Update AdGuard Home with current ban list, with retry logic."""
        api_url = f"{ADGUARD_URL}/control/access/set"
        current_bans = list(self.banned_clients.keys())
        payload = {"disallowed_clients": current_bans}
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = requests.post(
                    api_url,
                    json=payload,
                    auth=(ADGUARD_USERNAME, ADGUARD_PASSWORD),
                    timeout=API_TIMEOUT
                )
                response.raise_for_status()
                
                logger.info(f"✓ AdGuard ban list synced. Active bans: {len(current_bans)}")
                self.api_retry_count = 0  # Reset retry counter on success
                return True
                
            except requests.exceptions.RequestException as e:
                self.api_retry_count += 1
                logger.warning(f"API sync attempt {attempt + 1} failed: {e}")
                
                if attempt < max_retries - 1:
                    time.sleep(API_RETRY_DELAY * (attempt + 1))  # Exponential backoff
        
        logger.error(f"Failed to sync bans after {max_retries} attempts")
        return False
    
    def initiate_ban(self, client_id: str, offending_ips: Set[str]):
        """Ban multiple IPs and sync with AdGuard Home."""
        logger.warning(f"🚨 Concurrent use detected for client '{client_id}'")
        logger.warning(f"   Banning IPs: {sorted(offending_ips)}")
        
        expiry_time = time.time() + BAN_DURATION
        
        for ip in offending_ips:
            self.banned_clients[ip] = expiry_time
            logger.info(f"   → Banned {ip} for {BAN_DURATION}s")
        
        # Clear the client's history to prevent further immediate triggers
        self.history.clear_client(client_id)
        
        # Update AdGuard Home
        self.update_adguard_bans()
    
    def check_for_expired_bans(self) -> bool:
        """Remove expired bans and return True if any were removed."""
        current_time = time.time()
        expired_ips = [
            ip for ip, expiry in self.banned_clients.items()
            if current_time > expiry
        ]
        
        if expired_ips:
            for ip in expired_ips:
                del self.banned_clients[ip]
                logger.info(f"✓ Ban expired for {ip}")
            
            logger.info(f"Removed {len(expired_ips)} expired bans, syncing with AdGuard")
            return self.update_adguard_bans()
        
        return False
    
    def process_log_entry(self, log_entry: str):
        """Process a single log entry with improved violation detection."""
        try:
            data = json.loads(log_entry)
            client_id = data.get("client_id")
            current_ip = data.get("client_ip")
            
            # Skip invalid entries or banned IPs
            if not client_id or not current_ip or current_ip in self.banned_clients:
                return
            
            current_time = time.time()
            history = self.history.get_history(client_id)
            
            # Clean old entries from this client's history
            while history and (current_time - history[0][0]) > TIME_WINDOW:
                history.popleft()
            
            # Violation detection: Check for concurrent usage
            if history:
                unique_ips_in_window = {ip for timestamp, ip in history}
                last_seen_ip = history[-1][1] if history else None
                
                # Violation: Different IP while others are still in the time window
                if current_ip not in unique_ips_in_window and len(unique_ips_in_window) > 0:
                    # Ban all IPs seen in the window plus the current one
                    all_offending_ips = unique_ips_in_window | {current_ip}
                    self.initiate_ban(client_id, all_offending_ips)
                    return
            
            # Add current entry to history
            self.history.add_entry(client_id, current_ip, current_time)
            
        except (json.JSONDecodeError, KeyError) as e:
            # Silently skip malformed entries (common with log rotation)
            pass
    
    def handle_log_rotation(self):
        """Detect and handle log file rotation."""
        try:
            current_stat = os.stat(ADGUARD_LOG_FILE)
            current_inode = current_stat.st_ino
            
            # If inode changed, file was rotated
            if self.log_file_inode and current_inode != self.log_file_inode:
                logger.info("Log file rotation detected, reopening...")
                if self.log_file_handle:
                    self.log_file_handle.close()
                
                self.log_file_handle = open(ADGUARD_LOG_FILE, "r")
                self.log_file_handle.seek(0, 2)  # Seek to end
                self.log_file_inode = current_inode
                return True
                
        except (OSError, IOError) as e:
            logger.error(f"Error handling log rotation: {e}")
            return False
        
        return False
    
    def run(self):
        """Main monitoring loop with comprehensive error handling."""
        if not self.validate_configuration():
            sys.exit(1)
        
        logger.info("🚀 Starting AdGuard Home IP Monitor (Enhanced)")
        logger.info(f"   Time window: {TIME_WINDOW}s, Ban duration: {BAN_DURATION}s")
        logger.info(f"   Max clients in memory: {MAX_CLIENTS_IN_MEMORY}")
        logger.info(f"   Monitoring: {ADGUARD_LOG_FILE}")
        
        try:
            # Open log file
            self.log_file_handle = open(ADGUARD_LOG_FILE, "r")
            self.log_file_handle.seek(0, 2)  # Seek to end
            self.log_file_inode = os.stat(ADGUARD_LOG_FILE).st_ino
            
            last_ban_check = time.time()
            last_rotation_check = time.time()
            
            while self.running:
                try:
                    # Check for log rotation every 30 seconds
                    if time.time() - last_rotation_check > 30:
                        self.handle_log_rotation()
                        last_rotation_check = time.time()
                    
                    # Read new log entries
                    line = self.log_file_handle.readline()
                    if line:
                        self.process_log_entry(line.strip())
                    else:
                        # No new data, brief sleep to prevent high CPU usage
                        time.sleep(0.1)
                    
                    current_time = time.time()
                    
                    # Check for expired bans every second
                    if current_time - last_ban_check > 1:
                        self.check_for_expired_bans()
                        last_ban_check = current_time
                    
                    # Periodic memory cleanup
                    self.history.periodic_cleanup(current_time)
                    
                except (OSError, IOError) as e:
                    logger.error(f"File I/O error: {e}")
                    time.sleep(1)
                    continue
                    
        except KeyboardInterrupt:
            logger.info("Monitor stopped by user")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            sys.exit(1)
        finally:
            if self.log_file_handle:
                self.log_file_handle.close()
            logger.info("AdGuard Monitor stopped")

# ==============================================================================
# --- ENTRY POINT ---
# ==============================================================================

def main():
    """Entry point with basic environment check."""
    if os.geteuid() == 0:
        logger.warning("⚠️  Running as root - consider using a dedicated user account")
    
    monitor = AdGuardMonitor()
    monitor.run()

if __name__ == "__main__":
    main()
