import os
import hashlib
import requests
import json

class VtDirScan:
    def __init__(self):
        self.directory_path = None
        self.allowed_extensions = None

    def set_directory_path(self, directory_path):
        self.directory_path = directory_path

    def set_allowed_extensions(self, allowed_extensions):
        self.allowed_extensions = allowed_extensions

    def calculate_hash(self, file_path, algorithm='sha256', buffer_size=8192):
        hash_object = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(buffer_size)
                if not data:
                    break
                hash_object.update(data)
        return hash_object.hexdigest()

    def hash_files_in_directory(self, algorithm='sha256'):
        if not self.directory_path:
            raise ValueError("Directory path is not set. Use set_directory_path method.")

        file_hashes = {}
        for root, dirs, files in os.walk(self.directory_path):
            for file in files:
                file_path = os.path.join(root, file)

                if self.allowed_extensions and not any(file_path.endswith(ext) for ext in self.allowed_extensions):
                    continue

                file_hash = self.calculate_hash(file_path, algorithm)
                file_hashes[file_path] = file_hash

        return file_hashes

    def vt_scan(self, file_hashes):
        vt_scanresults = []
        filehash = list(file_hashes.values())
        for i in filehash:
            url = f"https://www.virustotal.com/ui/files/{i}"
            headers = {
                "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
                "X-Tool": "vt-ui-main",
                "X-VT-Anti-Abuse-Header": "MTA3OTM2NjUwMjctWkc5dWRDQmlaU0JsZG1scy0xNjMxMTE3NzQyLjY1",
                "Accept-Ianguage": "en-US,en;q=0.9,es;q=0.8",
            }
            data = requests.get(url, headers=headers).json()
            vt_scanresults.append(data)
            
        return vt_scanresults

    def virus_or_not(self, vt_scanresults):
        result = []
        malwareinfo = []
        for i in vt_scanresults:
            currentloop_malwareinfo = []
            for key, value in i.items():
                if "notfounderror" in str(value).lower():
                    x = "safe"
                    result.append(x)
                    currentloop_malwareinfo.append(x)
                else:
                    x = "malware detected"
                    result.append(x)
                    
                    dump_vtresult = json.dumps(i)
                    load_vtresult = json.loads(dump_vtresult)

                    threat_category = []
                    for i in load_vtresult["data"]["attributes"]["popular_threat_classification"]["popular_threat_category"]:
                        threat_category.append(i["value"])

                    threat_label = load_vtresult["data"]["attributes"]["popular_threat_classification"]["suggested_threat_label"]
                    filetype = load_vtresult["data"]["attributes"]["type_description"]
                    size = load_vtresult["data"]["attributes"]["size"]
                    hashes = load_vtresult["data"]["attributes"]["sha256"]
                    vt_link = f'https://www.virustotal.com/gui/file/{hashes}'
                    
                    currentloop_malwareinfo.extend([threat_label, threat_category, size, filetype, hashes, vt_link])

            malwareinfo.append(currentloop_malwareinfo)

        return result, malwareinfo

    def show_res(self, file_hashes, result, malwareinfo):
        reshow = []
        for key, status, info in zip(file_hashes.keys(), result, malwareinfo):
            reshow.append((key, file_hashes[key], status, info))

        return reshow

    def remove_malware(self, reshow):
        for item in reshow:
            if 'malware detected' in item:
                malzdir = item[0]
                decision = input(f"delete malware ({malzdir}) (y or n) ? ")
                x = True
                while x == True:
                    if decision == 'y':
                        os.remove(malzdir)
                        x = False
                    elif decision == 'n':
                        x = False
                    else:
                        print("select y or n bruh")
            else:
                pass

    def run_scan(self):
        file_hashes = self.hash_files_in_directory()
        print('\nFile scanned : ')
        for file_path, file_hash in file_hashes.items():
            print(f"{file_path}: {file_hash}")
        
        vt_scanresults = self.vt_scan(file_hashes)
        result, info = self.virus_or_not(vt_scanresults)

        reshow = self.show_res(file_hashes, result, info)
        print(f'\nScan Results : ')
        for result in reshow:
            file_path, sha256, status, details = result
            print(f'File Path: {file_path}')
            print(f'SHA256: {sha256}')
            print(f'Status: {status}')

            if status == 'malware detected':
                threat_label, threat_category, size, filetype, hashes, vt_link = details
                print(f'Threat Label: {threat_label}')
                print(f'Threat Category: {threat_category}')
                print(f'Size: {size}')
                print(f'File Type: {filetype}')
                print(f'Hashes: {hashes}')
                print(f'VirusTotal Link: {vt_link}')

            print('-' * 40)

        self.remove_malware(reshow)


banner = """
___    ___________________       ________                    
__ |  / /_  /___  __ \__(_)________  ___/___________ _________
__ | / /_  __/_  / / /_  /__  ___/____ \_  ___/  __ `/_  __  /
__ |/ / / /_ _  /_/ /_  / _  /   ____/ // /__ / /_/ /_  / / /
_____/  \__/ /_____/ /_/  /_/    /____/ \___/ \__,_/ /_/ /_/
Malware Scanner by Scraping VirusTotal
"""
print(banner)

path = input('Enter dir path to scan: ')
extensions = []
while True:
    ext = input("Enter extension to scan (enter F to scan all or when u done entering ext): ")
    if ext.lower() == 'f':
        break
    extensions.append(f'.{ext}')

scan = VtDirScan()
scan.set_directory_path(path)
scan.set_allowed_extensions(extensions)

scan.run_scan()
