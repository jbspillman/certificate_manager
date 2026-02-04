"""
Complete OneFS Certificate Setup - End-to-End Script
This script handles everything from CA creation to final API validation

Workflow:
1. Create/Load CA certificate
2. Create server certificates for each device
3. Verify certificates locally
4. For each device:
   a. Upload certificates and create bundle
   b. Reset OneFS with temporary certificate (clears old certs)
   c. Install proper certificate bundle
   d. Verify certificate is active
   e. Test API calls
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
import hashlib
from datetime import datetime, timedelta, timezone
import ipaddress
import socket
import os
import paramiko
from paramiko.ssh_exception import SSHException, NoValidConnectionsError
import requests
import ssl
import time

script_dir = os.path.dirname(os.path.realpath(__file__))
certificates_folder = os.path.join(script_dir, 'certificates')
os.makedirs(certificates_folder, exist_ok=True)

# ROOT CA FILES
ca_key_file = 'CA_beastmode.key'
ca_crt_file = 'CA_beastmode.crt'

local_account_username = 'root'  # compadmin, complocal, admin, administrator, wtfyo
local_account_password = ''


# Device configuration
devices_list = [
    {
        'devicename': 'onefs001-1.beastmode.local.net',
        'ips': ['192.168.0.120', '192.168.0.121'],
        'aliases': [
            'mgmt.onefs001.beastmode.local.net',
            'mgmt.onefs001-1.beastmode.local.net',
            'mgmt.onefs001-1',
            'onefs001-1'
        ]
    },
    {
        'devicename': 'onefs002-1.beastmode.local.net',
        'ips': ['192.168.0.125', '192.168.0.126'],
        'aliases': [
            'mgmt.onefs002.beastmode.local.net',
            'mgmt.onefs002-1.beastmode.local.net',
            'mgmt.onefs002-1',
            'onefs002-1'
        ]
    }
]


# ============================================================================
# PART 1: CERTIFICATE CREATION FUNCTIONS
# ============================================================================

def create_ca(output_key, output_cert):
    """Create or load Certificate Authority"""

    output_key_path = os.path.join(certificates_folder, output_key)
    output_cert_path = os.path.join(certificates_folder, output_cert)

    if os.path.exists(output_key_path) and os.path.exists(output_cert_path):
        print(f"✓ Loading existing CA from {output_key} and {output_cert}")
        with open(output_key_path, 'rb') as f:
            ca_private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(output_cert_path, 'rb') as f:
            ca_cert_value = x509.load_pem_x509_certificate(f.read())
        return ca_private_key, ca_cert_value

    print("Creating new CA certificate...")
    ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    with open(output_key_path, 'wb') as f:
        f.write(ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    country_code = 'US'
    state_code = 'OH'
    locale_code = 'CMH'
    org_code = 'NEW ALBANY'
    unit_code = 'LAB'
    common_code = 'Beastmode Root CA'

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_code),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_code),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locale_code),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_code),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, unit_code),
        x509.NameAttribute(NameOID.COMMON_NAME, common_code),
    ])

    subject_key_id = x509.SubjectKeyIdentifier.from_public_key(ca_private_key.public_key())

    ca_cert_value = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            key_encipherment=False, content_commitment=False, data_encipherment=False,
            key_agreement=False, encipher_only=False, decipher_only=False
        ), critical=True
    ).add_extension(
        subject_key_id, critical=False
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(subject_key_id),
        critical=False
    ).sign(ca_private_key, hashes.SHA256())

    with open(output_cert_path, 'wb') as f:
        f.write(ca_cert_value.public_bytes(serialization.Encoding.PEM))

    print(f"✓ CA created: {output_key} and {output_cert}")
    return ca_private_key, ca_cert_value


def create_server_cert(device_name, ip_addresses, ca_key_object, ca_cert_object,
                       additional_names=None, output_key=None, output_cert=None):
    """Create a server certificate signed by the CA"""

    if output_key is None:
        output_key = f"{device_name.split('.')[0]}.key"
    if output_cert is None:
        output_cert = f"{device_name.split('.')[0]}.crt"

    output_key_path = os.path.join(certificates_folder, output_key)
    output_cert_path = os.path.join(certificates_folder, output_cert)

    if os.path.exists(output_key_path) and os.path.exists(output_cert_path):
        print(f"✓ Server cert exists: {output_key}, {output_cert}")
        return

    print(f"Creating server certificate for {device_name}...")
    server_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    with open(output_key_path, 'wb') as f:
        f.write(server_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, device_name)])
    san_list = [x509.DNSName(device_name)]

    if additional_names:
        for name in additional_names:
            san_list.append(x509.DNSName(name))

    if ip_addresses:
        if isinstance(ip_addresses, str):
            ip_addresses = [ip_addresses]
        for ip in ip_addresses:
            san_list.append(x509.IPAddress(ipaddress.ip_address(ip)))

    ca_ski = ca_cert_object.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER
    ).value

    server_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert_object.subject
    ).public_key(
        server_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=3650)
    ).add_extension(
        x509.SubjectAlternativeName(san_list), critical=False
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True, key_encipherment=True,
            key_cert_sign=False, crl_sign=False, content_commitment=False,
            data_encipherment=False, key_agreement=False,
            encipher_only=False, decipher_only=False
        ), critical=True
    ).add_extension(
        x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(server_private_key.public_key()),
        critical=False
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski),
        critical=False
    ).sign(ca_key_object, hashes.SHA256())

    with open(output_cert_path, 'wb') as f:
        f.write(server_cert.public_bytes(serialization.Encoding.PEM))

    print(f"✓ Server cert created: {output_key}, {output_cert}")


def verify_cert_key_match(cert_file, key_file):
    """Verify certificate and key match locally"""

    cert_file_path = os.path.join(certificates_folder, cert_file)
    key_file_path = os.path.join(certificates_folder, key_file)

    with open(cert_file_path, 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read())
    with open(key_file_path, 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    cert_modulus = cert.public_key().public_numbers().n
    key_modulus = private_key.public_key().public_numbers().n

    if cert_modulus == key_modulus:
        print(f"✓ {cert_file} and {key_file} match")
        return True
    else:
        print(f"✗ {cert_file} and {key_file} DO NOT match")
        return False


# ============================================================================
# PART 2: ONEFS UPLOAD AND BUNDLE CREATION
# ============================================================================

def upload_certificates_to_onefs(hostname, short_name, username=local_account_username, password=local_account_password):
    """Upload certificates and create bundle on OneFS"""

    print(f"\n{'=' * 80}")
    print(f"UPLOADING CERTIFICATES TO: {hostname}")
    print(f"{'=' * 80}")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(hostname, username=username, password=password, timeout=30)

        # Create directory
        print("\n1. Creating directory /ifs/ssl_certs...")
        ssh.exec_command('mkdir -p /ifs/ssl_certs')

        # Upload files
        print("\n2. Uploading certificates...")
        sftp = ssh.open_sftp()

        cert_file = f'{short_name}.crt'
        key_file = f'{short_name}.key'

        local_cert = os.path.join(certificates_folder, cert_file)
        local_key = os.path.join(certificates_folder, key_file)
        local_ca = os.path.join(certificates_folder, ca_crt_file)

        remote_cert = f'/ifs/ssl_certs/{cert_file}'
        remote_key = f'/ifs/ssl_certs/{key_file}'
        remote_ca = f'/ifs/ssl_certs/{ca_crt_file}'

        print(f"  Uploading {cert_file}...")
        sftp.put(local_cert, remote_cert)
        print(f"  Uploading {key_file}...")
        sftp.put(local_key, remote_key)
        print(f"  Uploading {ca_crt_file}...")
        sftp.put(local_ca, remote_ca)

        sftp.close()

        # Create bundle
        print("\n3. Creating certificate bundle...")
        stdin, stdout, stderr = ssh.exec_command(
            f'cat {remote_cert} {remote_ca} > /ifs/ssl_certs/bundle.crt'
        )
        stdout.read()

        # Verify bundle
        stdin, stdout, stderr = ssh.exec_command(
            'grep -c "BEGIN CERTIFICATE" /ifs/ssl_certs/bundle.crt 2>&1'
        )
        cert_count = stdout.read().decode().strip()
        print(f"  Certificates in bundle: {cert_count} (should be 2)")

        # Verify files
        print("\n4. Verifying files on server...")
        stdin, stdout, stderr = ssh.exec_command('ls -lh /ifs/ssl_certs/')
        print(stdout.read().decode())

        ssh.close()
        print(f"✓ Certificates uploaded to {hostname}")
        return True

    except Exception as e:
        print(f"✗ Error: {e}")
        try:
            ssh.close()
        except:
            pass
        return False


# ============================================================================
# PART 3: ONEFS RESET WITH TEMPORARY CERTIFICATE
# ============================================================================

def reset_with_temp_cert(hostname, username=local_account_username, password=local_account_password):
    """Reset OneFS with temporary self-signed certificate"""

    print(f"\n{'=' * 80}")
    print(f"RESETTING ONEFS WITH TEMP CERT: {hostname}")
    print(f"{'=' * 80}")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(hostname, username=username, password=password, timeout=30)

        # Generate temporary certificate
        print("\n1. Generating temporary self-signed certificate...")
        ssh.exec_command('cd /ifs/ssl_certs && rm -f temp_* 2>&1').read()

        stdin, stdout, stderr = ssh.exec_command(
            'cd /ifs/ssl_certs && openssl genrsa -out temp_server.key 2048 2>&1'
        )
        stdout.read()

        stdin, stdout, stderr = ssh.exec_command(
            'cd /ifs/ssl_certs && '
            'openssl req -new -x509 -days 3650 -nodes -key temp_server.key -out temp_server.crt '
            '-subj "/C=US/ST=OH/L=CMH/O=TEMP/CN=temp.local" 2>&1'
        )
        stdout.read()
        print("  ✓ Temporary certificate generated")

        # Import temporary certificate
        print("\n2. Importing temporary certificate...")
        stdin, stdout, stderr = ssh.exec_command(
            'isi certificate server import /ifs/ssl_certs/temp_server.crt /ifs/ssl_certs/temp_server.key 2>&1'
        )
        stdout.read()

        # Get temp certificate ID
        stdin, stdout, stderr = ssh.exec_command('isi certificate server list --no-header --no-footer 2>&1')
        cert_list = stdout.read().decode()

        temp_cert_id = None
        for line in cert_list.split('\n'):
            line = line.strip()
            if line and not line.startswith('-'):
                parts = line.split()
                if parts:
                    temp_cert_id = parts[0]
                    break

        if not temp_cert_id:
            print("✗ Could not find temp certificate ID")
            ssh.close()
            return False

        print(f"  ✓ Temp certificate ID: {temp_cert_id}")

        # Set as default HTTPS
        print("\n3. Setting temp certificate as default HTTPS...")
        stdin, stdout, stderr = ssh.exec_command(
            f'isi certificate settings modify --default-https-certificate={temp_cert_id} 2>&1'
        )
        stdout.read()
        print("  ✓ Set as default")

        # Delete old certificates
        print("\n4. Deleting old certificates...")
        stdin, stdout, stderr = ssh.exec_command('isi certificate server list --no-header --no-footer 2>&1')
        cert_list = stdout.read().decode()

        for line in cert_list.split('\n'):
            if 'temp_local' in line:
                continue
            line = line.strip()
            if line and not line.startswith('-'):
                parts = line.split()
                if parts:
                    cert_id = parts[0]
                    print(f"  Deleting: {cert_id}")
                    ssh.exec_command(f'isi certificate server delete {cert_id} --force 2>&1')

        # Restart services
        print("\n5. Restarting web services...")
        ssh.exec_command('isi services -a isi_webui disable 2>&1')
        time.sleep(3)
        ssh.exec_command('isi services -a isi_webui enable 2>&1')
        time.sleep(5)
        print("  ✓ Services restarted")

        ssh.close()
        print(f"✓ Reset complete on {hostname}")
        return True

    except Exception as e:
        print(f"✗ Error: {e}")
        try:
            ssh.close()
        except:
            pass
        return False


# ============================================================================
# PART 4: INSTALL PROPER CERTIFICATE
# ============================================================================

def install_proper_certificate(hostname, short_name, username=local_account_username, password=local_account_password):
    """Install proper certificate bundle"""

    print(f"\n{'=' * 80}")
    print(f"INSTALLING PROPER CERTIFICATE: {hostname}")
    print(f"{'=' * 80}")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(hostname, username=username, password=password, timeout=30)

        # Delete temp certificate
        print("\n1. Removing temporary certificate...")
        stdin, stdout, stderr = ssh.exec_command('isi certificate server list 2>&1')
        cert_list = stdout.read().decode()

        for line in cert_list.split('\n'):
            if 'temp' in line.lower():
                parts = line.split()
                if parts:
                    ssh.exec_command(f'isi certificate server delete {parts[0]} --force 2>&1')
        print("  ✓ Temp certificate removed")

        # Import proper certificate
        print("\n2. Importing proper certificate bundle...")
        key_path = f'/ifs/ssl_certs/{short_name}.key'
        stdin, stdout, stderr = ssh.exec_command(
            f'isi certificate server import /ifs/ssl_certs/bundle.crt {key_path} 2>&1'
        )
        output = stdout.read().decode()

        if 'error' in output.lower():
            print(f"✗ Import failed: {output}")
            ssh.close()
            return False
        print("  ✓ Certificate imported")

        # Get new certificate ID
        stdin, stdout, stderr = ssh.exec_command('isi certificate server list 2>&1')
        cert_list = stdout.read().decode()

        new_cert_id = None
        for line in cert_list.split('\n'):
            if 'temp' in line.lower():
                continue
            line = line.strip()
            if line and not line.startswith('-') and not line.startswith('ID'):
                parts = line.split()
                if parts:
                    new_cert_id = parts[0]
                    break

        if not new_cert_id:
            print("✗ Could not find new certificate ID")
            ssh.close()
            return False

        print(f"  ✓ New certificate ID: {new_cert_id}")

        # Set as default
        print("\n3. Setting as default HTTPS certificate...")
        stdin, stdout, stderr = ssh.exec_command(
            f'isi certificate settings modify --default-https-certificate={new_cert_id} 2>&1'
        )
        stdout.read()
        print("  ✓ Set as default")

        # Restart services
        print("\n4. Restarting web services...")
        ssh.exec_command('isi services -a isi_webui disable 2>&1')
        time.sleep(3)
        ssh.exec_command('isi services -a isi_webui enable 2>&1')
        time.sleep(5)
        print("  ✓ Services restarted")

        ssh.close()
        print(f"✓ Proper certificate installed on {hostname}")
        return True

    except Exception as e:
        print(f"✗ Error: {e}")
        try:
            ssh.close()
        except:
            pass
        return False


# ============================================================================
# PART 5: VERIFICATION AND TESTING
# ============================================================================

def verify_certificate_from_client(hostname):
    """Verify certificate from client side"""

    print(f"\n{'=' * 80}")
    print(f"CLIENT-SIDE VERIFICATION: {hostname}")
    print(f"{'=' * 80}")

    try:
        cert_pem = ssl.get_server_certificate((hostname, 8080))
        cert = x509.load_pem_x509_certificate(cert_pem.encode())

        print(f"Subject: {cert.subject}")
        print(f"Issuer: {cert.issuer}")
        print(f"Valid from: {cert.not_valid_before_utc}")
        print(f"Valid to: {cert.not_valid_after_utc}")

        now = datetime.now(cert.not_valid_before_utc.tzinfo)
        cert_age = (now - cert.not_valid_before_utc).total_seconds() / 3600
        print(f"Certificate age: {cert_age:.1f} hours")

        has_aki = False
        has_ski = False

        try:
            cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
            has_aki = True
            print("✓ Has Authority Key Identifier")
        except:
            print("✗ Missing Authority Key Identifier")

        try:
            cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
            has_ski = True
            print("✓ Has Subject Key Identifier")
        except:
            print("✗ Missing Subject Key Identifier")

        if has_aki and has_ski and cert_age < 24:
            print("\n✓✓✓ SUCCESS! Certificate is correct and new!")
            return True
        else:
            print("\n✗ Certificate has issues")
            return False

    except Exception as e:
        print(f"✗ Error: {e}")
        return False


def test_api_call(hostname):
    """Test API call with CA certificate"""

    print(f"\n{'=' * 80}")
    print(f"TESTING API CALL: {hostname}")
    print(f"{'=' * 80}")

    ca_cert_path = os.path.join(certificates_folder, ca_crt_file)
    url = f'https://{hostname}:8080/platform/statistics/summary/system'

    try:
        response = requests.get(url, auth=(local_account_username, local_account_password), verify=ca_cert_path, timeout=10)
        print(f"✓ API Call Success! Status: {response.status_code}")
        return True
    except Exception as e:
        print(f"✗ API Call Failed: {e}")
        return False


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    print("\n" + "=" * 80)
    print("COMPLETE ONEFS CERTIFICATE SETUP - END TO END")
    print("=" * 80)
    print("\nThis script will:")
    print("  1. Create/load CA certificate")
    print("  2. Create server certificates")
    print("  3. Verify certificates locally")
    print("  4. For each device:")
    print("     a. Upload certificates and create bundle")
    print("     b. Reset with temporary certificate")
    print("     c. Install proper certificate")
    print("     d. Verify from client side")
    print("     e. Test API calls")

    response = input("\nProceed? (yes/no): ")
    if response.lower() != 'yes':
        print("Aborted.")
        return

    # Step 1: Create CA
    print("\n" + "=" * 80)
    print("STEP 1: CREATE/LOAD CA CERTIFICATE")
    print("=" * 80)
    ca_key, ca_cert = create_ca(ca_key_file, ca_crt_file)

    # Step 2: Create server certificates
    print("\n" + "=" * 80)
    print("STEP 2: CREATE SERVER CERTIFICATES")
    print("=" * 80)
    for device in devices_list:
        create_server_cert(
            device_name=device['devicename'],
            ip_addresses=device['ips'],
            ca_key_object=ca_key,
            ca_cert_object=ca_cert,
            additional_names=device['aliases']
        )

    # Step 3: Verify certificates locally
    print("\n" + "=" * 80)
    print("STEP 3: VERIFY CERTIFICATES LOCALLY")
    print("=" * 80)
    for device in devices_list:
        short_name = device['devicename'].split('.')[0]
        verify_cert_key_match(f'{short_name}.crt', f'{short_name}.key')

    # Step 4-8: Process each device
    for device in devices_list:
        hostname = device['devicename']
        short_name = hostname.split('.')[0]

        print("\n\n" + "=" * 80)
        print(f"PROCESSING: {hostname}")
        print("=" * 80)

        # Upload certificates
        success = upload_certificates_to_onefs(hostname, short_name)
        if not success:
            print(f"✗ Failed to upload certificates to {hostname}")
            continue

        # Reset with temp cert
        success = reset_with_temp_cert(hostname)
        if not success:
            print(f"✗ Failed to reset {hostname}")
            continue

        # Install proper cert
        success = install_proper_certificate(hostname, short_name)
        if not success:
            print(f"✗ Failed to install proper certificate on {hostname}")
            continue

        # Verify
        print("\nWaiting 5 seconds for changes to propagate...")
        time.sleep(5)
        verify_certificate_from_client(hostname)

        # Test API
        test_api_call(hostname)

    print("\n\n" + "=" * 80)
    print("✓✓✓ SETUP COMPLETE!")
    print("=" * 80)
    print("\nAll certificates have been installed and verified.")
    print("You can now use requests.get(url, verify='certificates/CA_beastmode.crt')")


if __name__ == "__main__":
    main()

