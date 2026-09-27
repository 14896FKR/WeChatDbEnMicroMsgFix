#!/usr/bin/env python3
"""
WeChat Database Decryptor
Extracts encryption keys and decrypts WCDB databases

Usage:
    # Auto mode: extract key and decrypt (auto-find DB)
    python wechat_decrypt.py /path/to/com.tencent.mm
    
    # Auto mode with specific DB file
    python wechat_decrypt.py /path/to/com.tencent.mm /path/to/EnMicroMsg.db
    
    # Extract key only
    python wechat_decrypt.py /path/to/com.tencent.mm --extract-key-only
    
    # Decrypt with known key
    python wechat_decrypt.py /path/to/EnMicroMsg.db --key 1277f69
"""

import os
import re
import sys
import argparse
import hmac
import hashlib
import struct
from hashlib import md5

# Cryptography imports
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Cipher import ARC4

try:
    import javaobj
    HAS_JAVAOBJ = True
except ImportError:
    HAS_JAVAOBJ = False

# ============================================================================
# Configuration
# ============================================================================

RC4_KEY = b"_wEcHAT_"
FALLBACK_IMEI = "1234567890ABCDEF"

CIPHER_PAGE_SIZE = 1024
KDF_ITER = 4000
IV_SIZE = 16
KEY_SIZE = 32
AES_BLOCK_SIZE = 16
SQLITE_HEADER = b"SQLite format 3"

# ============================================================================
# Helper Functions
# ============================================================================

def find_databases(wechat_dir, user_id=None):
    """Find all EnMicroMsg.db files in WeChat directory"""
    databases = []
    micromsg_dir = os.path.join(wechat_dir, "MicroMsg")
    
    if not os.path.isdir(micromsg_dir):
        return databases
    
    # Find all user directories (32-char hex strings)
    for item in os.listdir(micromsg_dir):
        item_path = os.path.join(micromsg_dir, item)
        
        # Skip if not a directory or doesn't match user_id filter
        if not os.path.isdir(item_path):
            continue
        
        if user_id and item != user_id:
            continue
        
        # Check for EnMicroMsg.db
        db_path = os.path.join(item_path, "EnMicroMsg.db")
        if os.path.isfile(db_path):
            databases.append({
                'path': db_path,
                'user_id': item,
                'size': os.path.getsize(db_path)
            })
    
    return databases


# ============================================================================
# Key Extraction Functions
# ============================================================================

def extract_uin(wechat_dir, verbose=True):
    """Extract UIN from WeChat data"""
    candidates = set()
    
    xml_files = [
        "shared_prefs/system_config_prefs.xml",
        "shared_prefs/auth_info_key_prefs.xml",
        "shared_prefs/com.tencent.mm_preferences.xml",
    ]
    
    patterns = [
        rb'default_uin.*?value="(\d+)"',
        rb'auth_uin.*?value="(\d+)"',
        rb'last_login_uin.*?>(\d+)<',
    ]
    
    for rel_path in xml_files:
        full_path = os.path.join(wechat_dir, rel_path)
        if not os.path.isfile(full_path):
            continue
        
        data = open(full_path, "rb").read()
        for pattern in patterns:
            for match in re.findall(pattern, data):
                candidates.add(match.decode())
    
    # Try systemInfo.cfg
    cfg_path = os.path.join(wechat_dir, "MicroMsg/systemInfo.cfg")
    if os.path.isfile(cfg_path) and HAS_JAVAOBJ:
        try:
            uin = javaobj.load(open(cfg_path, "rb")).get(1, 0)
            if uin:
                candidates.add(str(uin))
        except:
            pass
    
    result = list(candidates)
    if verbose:
        print(f"[+] Found {len(result)} UIN(s): {result}")
    
    return result


def extract_imei(wechat_dir, verbose=True):
    """Extract IMEI from WeChat data"""
    imeis = set()
    
    # Extract from keyinfo.bin
    keyinfo_path = os.path.join(wechat_dir, "files/keyinfo.bin")
    if os.path.isfile(keyinfo_path):
        try:
            encrypted = open(keyinfo_path, "rb").read()
            decrypted = ARC4.new(RC4_KEY).decrypt(encrypted)
            
            if verbose:
                print(f"[+] keyinfo.bin decrypted")
            
            for match in re.findall(rb"[0-9A-Z]{14,20}", decrypted):
                try:
                    imeis.add(match.decode("ascii"))
                except:
                    pass
        except Exception as e:
            if verbose:
                print(f"[!] Failed to decrypt keyinfo.bin: {e}")
    else:
        if verbose:
            print("[!] keyinfo.bin not found")
    
    # Extract from CompatibleInfo.cfg
    cfg_path = os.path.join(wechat_dir, "MicroMsg/CompatibleInfo.cfg")
    if os.path.isfile(cfg_path) and HAS_JAVAOBJ:
        try:
            imei = javaobj.load(open(cfg_path, "rb"))[258]
            if imei:
                imeis.add(imei)
        except:
            pass
    
    if not imeis:
        if verbose:
            print(f"[!] No IMEI found, using fallback: {FALLBACK_IMEI}")
        imeis.add(FALLBACK_IMEI)
    
    result = list(imeis)
    if verbose:
        print(f"[+] Found {len(result)} IMEI(s): {result}")
    
    return result


def generate_key(imei, uin):
    """Generate encryption key from IMEI and UIN"""
    if isinstance(uin, str):
        uin = uin.encode("ascii")
    if isinstance(imei, str):
        imei = imei.encode("ascii")
    
    return md5(imei + uin).hexdigest()[:7]


def extract_keys(wechat_dir, verbose=True):
    """Extract all possible encryption keys"""
    uins = extract_uin(wechat_dir, verbose)
    imeis = extract_imei(wechat_dir, verbose)
    
    keys = []
    for uin in uins:
        for imei in imeis:
            key = generate_key(imei, uin)
            keys.append({
                'imei': imei,
                'uin': uin,
                'key': key
            })
    
    return keys


# ============================================================================
# Database Decryption Functions
# ============================================================================

def pbkdf2_hmac_sha1(password, salt, iterations, length):
    """Derive key using PBKDF2-HMAC-SHA1"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=length,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password)


def decrypt_aes_cbc(key, iv, data):
    """Decrypt data using AES-CBC"""
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()


def decrypt_database(db_path, password, page_size=CIPHER_PAGE_SIZE, 
                     kdf_iterations=KDF_ITER, verbose=True):
    """Decrypt WeChat WCDB database (NO HMAC version - exact implementation)"""
    with open(db_path, 'rb') as f:
        buf = f.read()
    
    # Check if already decrypted
    if buf.startswith(SQLITE_HEADER):
        if verbose:
            print("[*] Database is already decrypted")
        return buf
    
    # Extract salt (first 16 bytes)
    salt = buf[:IV_SIZE]
    if verbose:
        print(f"[+] Salt (hex): {salt.hex()}")
    
    # Convert password to bytes
    pass_key = password.encode('utf-8')
    if verbose:
        print(f"[+] Password: {password}")
    
    # Generate AES key
    aes_key = pbkdf2_hmac_sha1(pass_key, salt, kdf_iterations, KEY_SIZE)
    if verbose:
        print(f"[+] AES Key (hex): {aes_key.hex()}")
    
    # Reserve size = IV only (NO HMAC)
    reserve_size = IV_SIZE
    if verbose:
        print(f"\n[+] Page size: {page_size}")
        print(f"[+] Reserve size: {reserve_size} (IV only)")
        print(f"[+] Encrypted data size per page: {page_size - reserve_size}\n")
    
    # Initialize output buffer
    decrypted_buf = bytearray()
    
    # Add SQLite header
    decrypted_buf.extend(SQLITE_HEADER)
    decrypted_buf.append(0x00)
    
    # Calculate total pages
    total_pages = len(buf) // page_size
    if len(buf) % page_size != 0:
        total_pages += 1
    
    if verbose:
        print(f"[+] Total pages: {total_pages}\n")
    
    # Decrypt each page
    for page_num in range(total_pages):
        page_offset = page_num * page_size
        page_end = min(page_offset + page_size, len(buf))
        page_data = buf[page_offset:page_end]
        
        # First page: skip salt (16 bytes)
        if page_num == 0:
            start_offset = IV_SIZE
        else:
            start_offset = 0
        
        # Check for empty pages
        if len(page_data) < reserve_size + start_offset:
            decrypted_buf.extend(page_data)
            continue
        
        if all(b == 0 for b in page_data):
            decrypted_buf.extend(page_data)
            break
        
        # Calculate data size
        data_size = len(page_data) - reserve_size
        
        # Extract IV (last 16 bytes of page)
        iv = page_data[data_size:data_size + IV_SIZE]
        
        # Extract encrypted data
        encrypted_data = page_data[start_offset:data_size]
        
        if verbose and page_num < 3:  # Debug info for first 3 pages
            print(f"[*] Page {page_num + 1}:")
            print(f"    Start offset: {start_offset}")
            print(f"    Encrypted data size: {len(encrypted_data)}")
            print(f"    IV: {iv.hex()}")
        
        try:
            # AES-CBC decryption
            decrypted_page = decrypt_aes_cbc(aes_key, iv, encrypted_data)
            
            # Check first page decryption result
            if verbose and page_num == 0:
                print(f"\n[*] First page decryption result (first 32 bytes):")
                print(f"    {decrypted_page[:32]}")
                print(f"    Hex: {decrypted_page[:32].hex()}")
                if decrypted_page.startswith(b'SQLite format 3'):
                    print("    ✓ SQLite header found!")
                else:
                    print("    ✗ No SQLite header")
            
            decrypted_buf.extend(decrypted_page)
            
            # Add reserve area (IV)
            decrypted_buf.extend(page_data[data_size:])
            
            if verbose and (page_num + 1) % 200 == 0:
                print(f"\n[*] Progress: {page_num + 1}/{total_pages} pages")
        
        except Exception as e:
            print(f"\n[!] Page {page_num + 1} decryption error: {e}")
            if verbose:
                import traceback
                traceback.print_exc()
            raise
    
    return bytes(decrypted_buf)


# ============================================================================
# Main Function
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='WeChat Database Decryptor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto mode: extract key and decrypt (auto-find DB)
  python wechat_decrypt.py /path/to/com.tencent.mm
  
  # Auto mode with specific DB file
  python wechat_decrypt.py /path/to/com.tencent.mm /path/to/EnMicroMsg.db
  
  # Specify user ID
  python wechat_decrypt.py /path/to/com.tencent.mm --user-id abc123def456
  
  # Extract key only
  python wechat_decrypt.py /path/to/com.tencent.mm --extract-key-only
  
  # Decrypt with known key
  python wechat_decrypt.py /path/to/EnMicroMsg.db --key 1277f69
  
  # Try all possible keys
  python wechat_decrypt.py /path/to/com.tencent.mm --try-all
        """
    )
    
    parser.add_argument(
        'path1',
        help='WeChat directory (com.tencent.mm) or database file'
    )
    
    parser.add_argument(
        'path2',
        nargs='?',
        help='Database file (optional, auto-detected if not provided)'
    )
    
    parser.add_argument(
        '--user-id',
        help='Specific WeChat user ID (32-char hex in MicroMsg folder)'
    )
    
    parser.add_argument(
        '--key',
        help='Encryption key (if already known)'
    )
    
    parser.add_argument(
        '--extract-key-only',
        action='store_true',
        help='Only extract keys without decrypting'
    )
    
    parser.add_argument(
        '--try-all',
        action='store_true',
        help='Try all extracted keys until one succeeds'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output file path (default: decrypted_<input>)'
    )
    
    parser.add_argument(
        '--page-size',
        type=int,
        default=CIPHER_PAGE_SIZE,
        help=f'Database page size (default: {CIPHER_PAGE_SIZE})'
    )
    
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress detailed output'
    )
    
    args = parser.parse_args()
    verbose = not args.quiet
    
    try:
        # Mode 1: Decrypt with known key
        if args.key:
            db_path = args.path1
            
            if not os.path.isfile(db_path):
                print(f"[!] Error: Database file not found: {db_path}", file=sys.stderr)
                return 1
            
            output_path = args.output or f"decrypted_{os.path.basename(db_path)}"
            
            print("=" * 60)
            print("WeChat Database Decryptor - Decrypt Mode")
            print("=" * 60)
            print(f"Input:  {db_path}")
            print(f"Output: {output_path}")
            print(f"Key:    {args.key}")
            print("=" * 60 + "\n")
            
            decrypted_data = decrypt_database(db_path, args.key, args.page_size, 
                                             KDF_ITER, verbose)
            
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            print("\n" + "=" * 60)
            if decrypted_data.startswith(SQLITE_HEADER):
                print("✓ Decryption successful!")
                print(f"✓ Output: {output_path}")
                print(f"✓ File size: {len(decrypted_data):,} bytes")
                print("\n[*] File header:")
                print(f"    First 64 bytes: {decrypted_data[:64]}")
                print(f"    Hex: {decrypted_data[:64].hex()}")
                print("\n✓ SQLite header verified - decryption successful!")
                print(f"\n[*] Open with: sqlite3 {output_path}")
            else:
                print("⚠ Warning: SQLite header not found")
                print(f"    First 64 bytes: {decrypted_data[:64]}")
                print(f"    Hex: {decrypted_data[:64].hex()}")
                print("  Decryption may have failed or wrong key used")
            print("=" * 60)
            
            return 0
        
        # Mode 2: Extract key only
        elif args.extract_key_only:
            wechat_dir = args.path1
            
            if not os.path.isdir(wechat_dir):
                print(f"[!] Error: Directory not found: {wechat_dir}", file=sys.stderr)
                return 1
            
            print("=" * 60)
            print("WeChat Database Decryptor - Key Extraction")
            print("=" * 60 + "\n")
            
            keys = extract_keys(wechat_dir, verbose)
            
            print("\n" + "=" * 60)
            print("Possible Encryption Keys")
            print("=" * 60)
            
            for key_info in keys:
                print(f"IMEI: {key_info['imei']}")
                print(f"UIN:  {key_info['uin']}")
                print(f"KEY:  {key_info['key']}")
                print("-" * 60)
            
            print(f"\n[*] Total: {len(keys)} possible key(s)")
            print("[*] Use these keys with: python wechat_decrypt.py <db_file> --key <KEY>")
            
            return 0
        
        # Mode 3: Auto mode (extract + decrypt)
        else:
            wechat_dir = args.path1
            
            if not os.path.isdir(wechat_dir):
                print(f"[!] Error: WeChat directory not found: {wechat_dir}", file=sys.stderr)
                return 1
            
            # Find databases if not specified
            if not args.path2:
                if verbose:
                    print("[*] Searching for EnMicroMsg.db files...")
                
                databases = find_databases(wechat_dir, args.user_id)
                
                if not databases:
                    print("[!] Error: No EnMicroMsg.db files found", file=sys.stderr)
                    print(f"[*] Searched in: {os.path.join(wechat_dir, 'MicroMsg')}/<user_id>/", file=sys.stderr)
                    return 1
                
                if len(databases) > 1 and not args.user_id:
                    print(f"[*] Found {len(databases)} database(s):")
                    for i, db in enumerate(databases, 1):
                        print(f"    {i}. {db['user_id']} ({db['size']:,} bytes)")
                    print("\n[*] Using first database. Use --user-id to specify.")
                    print(f"[*] Example: --user-id {databases[0]['user_id']}")
                
                db_path = databases[0]['path']
                
                if verbose:
                    print(f"[+] Found database: {db_path}")
            else:
                db_path = args.path2
            
            if not os.path.isfile(db_path):
                print(f"[!] Error: Database file not found: {db_path}", file=sys.stderr)
                return 1
            
            output_path = args.output or f"decrypted_{os.path.basename(db_path)}"
            
            print("=" * 70)
            print(" " * 20 + "WeChat Database Decryptor")
            print("=" * 70)
            
            # Extract keys
            print("\n[Step 1] Extracting encryption keys...")
            print("-" * 70)
            
            keys = extract_keys(wechat_dir, verbose)
            
            if not keys:
                print("\n[!] No keys could be extracted")
                return 1
            
            print(f"\n[+] Extracted {len(keys)} possible key(s)")
            for i, key_info in enumerate(keys, 1):
                print(f"    {i}. {key_info['key']} (IMEI: {key_info['imei']}, UIN: {key_info['uin']})")
            
            # Decrypt database
            print("\n[Step 2] Decrypting database...")
            print("-" * 70)
            print(f"Input:  {db_path}")
            print(f"Output: {output_path}")
            print("-" * 70 + "\n")
            
            success = False
            
            if args.try_all:
                # Try all keys
                for i, key_info in enumerate(keys, 1):
                    print(f"[Attempt {i}/{len(keys)}] Trying key: {key_info['key']}")
                    
                    try:
                        decrypted_data = decrypt_database(db_path, key_info['key'], 
                                                         args.page_size, KDF_ITER, False)
                        
                        if decrypted_data.startswith(SQLITE_HEADER):
                            print(f"✓ Success with key: {key_info['key']}")
                            
                            with open(output_path, 'wb') as f:
                                f.write(decrypted_data)
                            
                            success = True
                            break
                        else:
                            print(f"✗ Failed - invalid SQLite header")
                    except Exception as e:
                        print(f"✗ Failed - {e}")
            else:
                # Use first key only
                key_info = keys[0]
                print(f"Using key: {key_info['key']}")
                
                decrypted_data = decrypt_database(db_path, key_info['key'], 
                                                 args.page_size, KDF_ITER, verbose)
                
                with open(output_path, 'wb') as f:
                    f.write(decrypted_data)
                
                if decrypted_data.startswith(SQLITE_HEADER):
                    success = True
            
            # Final result
            print("\n" + "=" * 70)
            if success:
                print("✓ Decryption completed successfully!")
                print(f"✓ Output: {output_path}")
                print(f"✓ File size: {os.path.getsize(output_path):,} bytes")
                
                # Read and check file
                with open(output_path, 'rb') as f:
                    file_data = f.read(64)
                
                print("\n[*] File header:")
                print(f"    First 64 bytes: {file_data}")
                print(f"    Hex: {file_data.hex()}")
                
                if file_data.startswith(SQLITE_HEADER):
                    print("\n✓ SQLite header verified - decryption successful!")
                    print(f"\n[*] Open with: sqlite3 {output_path}")
                else:
                    print("\n⚠ No SQLite header - might need different key")
            else:
                print("✗ Decryption failed")
                if args.try_all:
                    print("  All keys failed. Check if the database is corrupted.")
                else:
                    print(f"  Try: python wechat_decrypt.py {wechat_dir} --try-all")
            print("=" * 70)
            
            return 0 if success else 1
    
    except Exception as e:
        print(f"\n[!] Error: {e}", file=sys.stderr)
        if verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())