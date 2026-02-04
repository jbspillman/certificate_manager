# Complete Certificate Setup - Quick Reference

## What This Script Does

This is a **single, unified end-to-end script** that combines:
- Certificate creation (from Create_CA_Install_v3.py)
- OneFS reset logic (from reset_and_reinstall.py)
- Installation and verification

## Workflow

### Phase 1: Local Certificate Creation
1. ✓ Create/load CA certificate with proper extensions (AKI, SKI)
2. ✓ Create server certificates for all devices
3. ✓ Verify certificates match their keys locally

### Phase 2: For Each Device
4. ✓ Upload certificates (server cert, key, CA cert) to OneFS
5. ✓ Create bundle (server cert + CA cert) on OneFS
6. ✓ Reset with temporary self-signed certificate
   - Generates temp cert on OneFS
   - Imports temp cert
   - Sets temp cert as default HTTPS
   - **Deletes all old certificates** (now safe to delete)
   - Restarts web services
7. ✓ Install proper certificate
   - Deletes temp cert
   - Imports proper bundle
   - Sets proper cert as default HTTPS
   - Restarts web services
8. ✓ Verify from client side
   - Checks certificate extensions (AKI, SKI)
   - Verifies certificate age (should be new)
9. ✓ Test API call
   - Tests actual HTTPS connection with CA validation

## Usage

```bash
python Complete_Certificate_Setup.py
```

Type `yes` when prompted.

## What Makes This Work

The key to success is the **reset with temporary certificate** step:
- Creates a clean slate by forcing OneFS to release old certificates
- Allows deletion of old certificates that were previously locked
- Ensures the new certificate is properly activated

## Expected Output

For each device:
```
CLIENT-SIDE VERIFICATION: onefs001-1.beastmode.local.net
================================================================================
Subject: <Name(CN=onefs001-1.beastmode.local.net)>
Issuer: <Name(C=US,ST=OH,L=CMH,O=HOME,OU=LAB,CN=Beastmode Root CA)>
Valid from: 2026-02-04 [current time]
Valid to: 2028-05-09 [future time]
Certificate age: 0.0 hours
✓ Has Authority Key Identifier
✓ Has Subject Key Identifier
✓✓✓ SUCCESS! Certificate is correct and new!

TESTING API CALL: onefs001-1.beastmode.local.net
================================================================================
✓ API Call Success! Status: 200
```

## Configuration

Edit the `devices_list` at the top of the script to add your clusters:

```python
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
    # Add more devices...
]
```

## Files Created

After running, you'll have:
```
certificates/
├── CA_beastmode.key          # CA private key (keep secure!)
├── CA_beastmode.crt          # CA certificate (use for verify=)
├── onefs001-1.key            # Device private key
├── onefs001-1.crt            # Device certificate
├── onefs002-1.key
├── onefs002-1.crt
└── ... (one pair per device)
```

## Using in Your Scripts

After setup, use the CA certificate for all API calls:

```python
import requests

response = requests.get(
    'https://onefs001-1.beastmode.local.net:8080/platform/statistics/summary/system',
    auth=('root', 'password'),
    verify='certificates/CA_beastmode.crt'  # ← Use this!
)
```

## Differences from Original Scripts

### vs Create_CA_Install_v3.py
- **Adds**: Automatic OneFS reset with temp certificate
- **Adds**: Proper certificate activation verification
- **Removes**: Separate activation step (now integrated)

### vs reset_and_reinstall.py
- **Adds**: Automatic certificate creation
- **Adds**: Certificate upload and bundle creation
- **Removes**: Requirement to run creation script first

## Troubleshooting

If any device fails:
1. Check the output for that specific device
2. Verify SSH connectivity (`ssh root@hostname`)
3. Ensure certificates were created locally (`ls certificates/`)
4. Run the script again (it will skip existing certificates)

## Time Estimate

- First device: ~2-3 minutes (includes CA creation)
- Additional devices: ~1-2 minutes each
- Total for 32 clusters: ~45-60 minutes

## Benefits of 10-year
Benefits of 10-year server certificates for your environment:
- ✅ Set it and forget it - No certificate rotation for a decade
- ✅ No production disruptions - No need to update 32 clusters every 2 years
- ✅ Virtual names are permanent - Unlike physical hosts that get replaced
- ✅ Internal infrastructure - Not exposed to public internet