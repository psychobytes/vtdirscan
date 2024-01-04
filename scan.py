import os
import hashlib
import requests
import json

class VtDirScan:
    def __init__(self, directory_path):
        self.directory_path = directory_path
        self.run_scan()

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
        file_hashes = {}
        for root, dirs, files in os.walk(self.directory_path):
            for file in files:
                file_path = os.path.join(root, file)
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
        with open('result2.json', 'w', encoding='utf-8') as f:
            json.dump(vt_scanresults, f, ensure_ascii=False, indent=4)
        return vt_scanresults

    def virus_or_not(self, vt_scanresults):
        result = []
        for i in vt_scanresults:
            for key, value in i.items():
                if "notfounderror" in str(value).lower():
                    x = "aman"
                    result.append(x)
                else:
                    x = "malware detected"
                    # sh = vt_scanresults[i]
                    # print(sh[data][attributes][total_votes][size])
                    result.append(x)
        return result

    def show_res(self, file_hashes, result):
        reshow = [(key, file_hashes[key], status) for key, status in zip(file_hashes.keys(), result)]
        return reshow

    def remove_malware(self, reshow):
        for item in reshow:
            if 'malware detected' in item:
                malzdir = item[0]
                decision = input(f"delete malware ({malzdir}) ? ")
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
        for file_path, file_hash in file_hashes.items():
            print(f"{file_path}: {file_hash}")
        
        vt_scanresults = self.vt_scan(file_hashes)
        #print(vt_scanresults)
        result = self.virus_or_not(vt_scanresults)
        #print(result)
        reshow = self.show_res(file_hashes, result)
        for i in reshow:
            print(i)
        self.remove_malware(reshow)

# Example Usage:
banner = """
___    ___________________       ________                    
__ |  / /_  /___  __ \__(_)________  ___/___________ ________
__ | / /_  __/_  / / /_  /__  ___/____ \_  ___/  __ `/_  __  /
__ |/ / / /_ _  /_/ /_  / _  /   ____/ // /__ / /_/ /_  / / /
_____/  \__/ /_____/ /_/  /_/    /____/ \___/ \__,_/ /_/ /_/
Malware Scanner Powered By VirusTotal"""
print(banner)
directory_path = input("Enter directory to scan: ")
scan = VtDirScan(directory_path)
# All methods are called automatically when the instance is created.
