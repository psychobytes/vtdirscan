# VtDirScan
![image](https://github.com/psychobytes/vtdirscan/assets/45039854/b35a1ef2-9378-482b-8be6-2811f4999ba4)

Scan malware to dir using py and virustotal

# Requirement :
- Python
- Internet connection
- pip install os, hashlib, requests, json

# How to Use :
1. python scan.py (run the program with python.)
2. Enter dir to scan.
3. Enter file extensions you want to scan (press f to scan all or when u done entering ext).
4. Wait until scanning process complete. Result will appear when scanning process complete.
5. If malware detected, you can delete it by enter 'y'. Enter 'n' if you dont want to delete the malware.
![image](https://github.com/psychobytes/vtdirscan/assets/45039854/e7ccc530-faaf-4f9c-8f87-5ebcb26a0d9d)

# How it Works :
- This program will read the sha256 hash value of the file you want to scan.
- Then, this program will compare the hash of the scanned file with the hash in VirusTotal.
- This program can detect all viruses that are already in the VirusTotal database.
- This program does not require a VirusTotal API key. You can use it directly.
