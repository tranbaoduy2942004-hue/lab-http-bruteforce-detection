# HTTP Authentication Brute Force Detection

Lab ID: lab-http-bruteforce-detection

## Topology
- attacker: 172.29.116.10
- web-server: 172.29.116.20
- soc: 172.29.116.30
- Network: HTTP_AUTH_NET
- HTTP Service: TCP 8080

## Objectives
1. Verify legitimate HTTP authentication.
2. Simulate six failed login attempts.
3. Collect HTTP authentication logs.
4. Detect brute force within 60 seconds.
5. Block the attacker IP and verify HTTP 403.

## Installation (HOST)
imodule https://raw.githubusercontent.com/tranbaoduy2942004-hue/lab-http-bruteforce-detection/main/imodule.tar
labtainer lab-http-bruteforce-detection

## Practice

### Attacker: Normal login
python3 /usr/local/bin/auth_client.py normal

### Attacker: Brute force
python3 /usr/local/bin/auth_client.py attack

### Web Server: Inspect logs
tail -n 10 /home/ubuntu/auth-lab/access.log

### SOC: Collect and detect
python3 /usr/local/bin/soc_auth.py collect
python3 /usr/local/bin/soc_auth.py detect

### SOC: Block attacker
python3 /usr/local/bin/soc_auth.py block

### Attacker: Verify blocking
python3 /usr/local/bin/auth_client.py verify

### HOST: Checkwork
checkwork lab-http-bruteforce-detection

Expected result: 5/5 Y

## Detection Logic
Five or more failed logins from the same IP
within 60 seconds trigger an alert.

## Safety
All requests remain inside the isolated Docker network.
No external targets or real password attacks.
