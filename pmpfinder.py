import re
import sys
import subprocess
import signal
import os

class SubdomainScanner:
    def __init__(self, domain):
        self.domain = domain
        self.process = None
        self.output_file = f"{domain}_amass_output.txt"
        self.report_dir = "report"
        self.create_report_directory()

    def create_report_directory(self):
        """'report' klasörünü oluşturur."""
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)

    def handle_interrupt(self, signal, frame):
        """Taramayı iptal etmek için kullanılan fonksiyon (Ctrl+C)."""
        if self.process:
            print("\nTaramayı iptal ediyorum...")
            self.process.terminate()  # Amass sürecini sonlandır
        print("Program sonlandırılıyor...")

    def amass_scan(self):
        """Amass taramasını çalıştırır ve çıktıyı dosyaya kaydeder."""
        try:
            print(f"Scanning the domain {self.domain}...")
            amass_command = ["amass", "enum", "-d", self.domain, "-o", self.output_file]
            self.process = subprocess.Popen(amass_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Çıktıyı okur ve dosyaya yazar, süreç devam ettiği sürece
            with open(self.output_file, "a") as file:
                while self.process.poll() is None:  
                    output = self.process.stdout.readline()  
                    if output:
                        file.write(output.decode())  
                self.process.wait()  
            print(f"Scan complete. Results saved in {self.output_file}.")
        except Exception as e:
            print(f"An error occurred: {str(e)}")

    def extract_subdomains_from_file(self):
        """Amass çıktısındaki subdomain'leri ayıklar."""
        try:
            with open(self.output_file, "r") as file:
                data = file.readlines()

            subdomains = set()
            for line in data:
                match = re.search(r'\b([a-zA-Z0-9.-]+\.' + re.escape(self.domain) + r'\b)', line)
                if match:
                    subdomains.add(match.group(1))

            return sorted(subdomains)
        except FileNotFoundError:
            print(f"File not found: {self.output_file}")
            return []

    def run_httprobe(self, subdomains):
        """Subdomain'leri kontrol etmek için httprobe çalıştırır."""
        print("\n[INFO] Starting HTTP probe...")
        
        
        process = subprocess.Popen(['httprobe'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate(input="\n".join(subdomains).encode())
        
        
        return stdout.decode().splitlines()

    def display_subdomains(self, subdomains):
        
        if subdomains:
            print(f"\nSubdomains found for {self.domain}:")
            for subdomain in subdomains:
                print(subdomain)
        else:
            print(f"No subdomains found for {self.domain}.")

    def display_http_subdomains(self, http_subdomains):
        """Aktif HTTP(S) subdomain'leri ekrana yazdırır."""
        if http_subdomains:
            print("\n[INFO] Active HTTP(S) subdomains:")
            for sub in http_subdomains:
                print(sub)
        else:
            print("[INFO] No active HTTP(S) subdomains found.")

    def save_to_report(self, subdomains, http_subdomains):
        """Sonuçları 'report' klasörüne kaydeder."""
        # Subdomain'leri dosyaya kaydet
        subdomains_file = os.path.join(self.report_dir, f"{self.domain}_subdomains.txt")
        with open(subdomains_file, "w") as file:
            for subdomain in subdomains:
                file.write(f"{subdomain}\n")
        print(f"Subdomains saved to {subdomains_file}.")

        # HTTP/S aktif subdomain'leri dosyaya kaydet
        http_subdomains_file = os.path.join(self.report_dir, f"{self.domain}_http_subdomains.txt")
        with open(http_subdomains_file, "w") as file:
            for subdomain in http_subdomains:
                file.write(f"{subdomain}\n")
        print(f"Active HTTP(S) subdomains saved to {http_subdomains_file}.")

    def remove_amass_output(self):
        """Temp Amass output dosyasını siler."""
        if os.path.exists(self.output_file):
            os.remove(self.output_file)
            print(f"{self.output_file} has been removed.")
    def generate_github_dorks(self,file_name):
        # Dosya adındaki uzantıyı kaldır
        without_suffix = file_name.split('.')[0]

        
        print("\n************ Github Dork Links (must be logged in) *******************")
        
        dorks = [
            ("password", [
                f"https://github.com/search?q=%22{file_name}%22+password&type=Code",
                f"https://github.com/search?q=%22{without_suffix}%22+password&type=Code"
            ]),
            ("npmrc _auth", [
                f"https://github.com/search?q=%22{file_name}%22+npmrc%20_auth&type=Code",
                f"https://github.com/search?q=%22{without_suffix}%22+npmrc%20_auth&type=Code"
            ]),
            ("dockercfg", [
                f"https://github.com/search?q=%22{file_name}%22+dockercfg&type=Code",
                f"https://github.com/search?q=%22{without_suffix}%22+dockercfg&type=Code"
            ]),
            ("pem private", [
                f"https://github.com/search?q=%22{file_name}%22+pem%20private&type=Code",
                f"https://github.com/search?q=%22{without_suffix}%22+extension:pem%20private&type=Code"
            ]),
            ("id_rsa", [
                f"https://github.com/search?q=%22{file_name}%22+id_rsa&type=Code",
                f"https://github.com/search?q=%22{without_suffix}%22+id_rsa&type=Code"
            ]),
            ("aws_access_key_id", [
                f"https://github.com/search?q=%22{file_name}%22+aws_access_key_id&type=Code",
                f"https://github.com/search?q=%22{without_suffix}%22+aws_access_key_id&type=Code"
            ]),
            ("s3cfg", [
                f"https://github.com/search?q=%22{file_name}%22+s3cfg&type=Code",
                f"https://github.com/search?q=%22{without_suffix}%22+s3cfg&type=Code"
            ]),
            ("htpasswd", [
                f"https://github.com/search?q=%22{file_name}%22+htpasswd&type=Code",
                f"https://github.com/search?q=%22{without_suffix}%22+htpasswd&type=Code"
            ]),
            ("git-credentials", [
                f"https://github.com/search?q=%22{file_name}%22+git-credentials&type=Code",
                f"https://github.com/search?q=%22{without_suffix}%22+git-credentials&type=Code"
            ]),
            ("bashrc password", [
                f"https://github.com/search?q=%22{file_name}%22+bashrc%20password&type=Code",
                f"https://github.com/search?q=%22{without_suffix}%22+bashrc%20password&type=Code"
            ]),
            ("sshd_config", [
                f"https://github.com/search?q=%22{file_name}%22+sshd_config&type=Code",
                f"https://github.com/search?q=%22{without_suffix}%22+sshd_config&type=Code"
            ]),
            ("xoxp OR xoxb OR xoxa", [
                f"https://github.com/search?q=%22{file_name}%22+xoxp%20OR%20xoxb%20OR%20xoxa&type=Code",
                f"https://github.com/search?q=%22{without_suffix}%22+xoxp%20OR%20xoxb&type=Code"
            ]),
            ("SECRET_KEY", [
                f"https://github.com/search?q=%22{file_name}%22+SECRET_KEY&type=Code",
                f"https://github.com/search?q=%22{without_suffix}%22+SECRET_KEY&type=Code"
            ]),
            ("client_secret", [
                f"https://github.com/search?q=%22{file_name}%22+client_secret&type=Code",
                f"https://github.com/search?q=%22{without_suffix}%22+client_secret&type=Code"
            ]),
            ("github_token", [
                f"https://github.com/search?q=%22{file_name}%22+github_token&type=Code",
                f"https://github.com/search?q=%22{without_suffix}%22+github_token&type=Code"
            ]),
            ("api_key", [
                f"https://github.com/search?q=%22{file_name}%22+api_key&type=Code",
                f"https://github.com/search?q=%22{without_suffix}%22+api_key&type=Code"
            ]),
            ("FTP", [
                f"https://github.com/search?q=%22{file_name}%22+FTP&type=Code",
                f"https://github.com/search?q=%22{without_suffix}%22+FTP&type=Code"
            ]),
            ("app_secret", [
                f"https://github.com/search?q=%22{file_name}%22+app_secret&type=Code",
                f"https://github.com/search?q=%22{without_suffix}%22+app_secret&type=Code"
            ]),
            ("passwd", [
                f"https://github.com/search?q=%22{file_name}%22+passwd&type=Code",
                f"https://github.com/search?q=%22{without_suffix}%22+passwd&type=Code"
            ]),
            (".env", [
                f"https://github.com/search?q=%22{file_name}%22+.env&type=Code",
                f"https://github.com/search?q=%22{without_suffix}%22+.env&type=Code"
            ]),
            (".exs", [
                f"https://github.com/search?q=%22{file_name}%22+.exs&type=Code",
                f"https://github.com/search?q=%22{without_suffix}%22+.exs&type=Code"
            ]),
            ("beanstalkd.yml", [
                f"https://github.com/search?q=%22{file_name}%22+beanstalkd.yml&type=Code",
                f"https://github.com/search?q=%22{without_suffix}%22+beanstalkd.yml&type=Code"
            ]),
            ("deploy.rake", [
                f"https://github.com/search?q=%22{file_name}%22+deploy.rake&type=Code",
                f"https://github.com/search?q=%22{without_suffix}%22+deploy.rake&type=Code"
            ]),
            ("mysql", [
                f"https://github.com/search?q=%22{file_name}%22+mysql&type=Code",
                f"https://github.com/search?q=%22{without_suffix}%22+mysql&type=Code"
            ]),
            ("credentials", [
                f"https://github.com/search?q=%22{file_name}%22+credentials&type=Code",
                f"https://github.com/search?q=%22{without_suffix}%22+credentials&type=Code"
            ]),
            ("PWD", [
                f"https://github.com/search?q=%22{file_name}%22+PWD&type=Code",
                f"https://github.com/search?q=%22{without_suffix}%22+PWD&type=Code"
            ]),
            (".bash_history", [
                f"https://github.com/search?q=%22{file_name}%22+.bash_history&type=Code",
                f"https://github.com/search?q=%22{without_suffix}%22+.bash_history&type=Code"
            ]),
            (".sls", [
                f"https://github.com/search?q=%22{file_name}%22+.sls&type=Code",
                f"https://github.com/search?q=%22{without_suffix}%22+PWD&type=Code"
            ]),
            ("secrets", [
                f"https://github.com/search?q=%22{file_name}%22+secrets&type=Code",
                f"https://github.com/search?q=%22{without_suffix}%22+secrets&type=Code"
            ]),
            ("composer.json", [
                f"https://github.com/search?q=%22{file_name}%22+composer.json&type=Code",
                f"https://github.com/search?q=%22{without_suffix}%22+composer.json&type=Code"
            ]),
        ]
        
        # Print each dork and save
        dork_file_path = os.path.join(self.report_dir, f"{self.domain}_git_dork.txt")
        with open(dork_file_path, "w") as file:
            for keyword, links in dorks:
                print(keyword)
                file.write(f"{keyword}:\n")
                for link in links:
                    file.write(f"{link}\n")
                    print(link)
                file.write("\n")

        print(f"Github Dorks saved to {dork_file_path}.")


def print_banner():
    
    banner = """

    
                                    /$$$$$$  /$$                 /$$                    
                                   /$$__  $$|__/                | $$                    
  /$$$$$$  /$$$$$$/$$$$   /$$$$$$ | $$  \__/ /$$ /$$$$$$$   /$$$$$$$  /$$$$$$   /$$$$$$ 
 /$$__  $$| $$_  $$_  $$ /$$__  $$| $$$$    | $$| $$__  $$ /$$__  $$ /$$__  $$ /$$__  $$
| $$  \ $$| $$ \ $$ \ $$| $$  \ $$| $$_/    | $$| $$  \ $$| $$  | $$| $$$$$$$$| $$  \__/
| $$  | $$| $$ | $$ | $$| $$  | $$| $$      | $$| $$  | $$| $$  | $$| $$_____/| $$      
| $$$$$$$/| $$ | $$ | $$| $$$$$$$/| $$      | $$| $$  | $$|  $$$$$$$|  $$$$$$$| $$      
| $$____/ |__/ |__/ |__/| $$____/ |__/      |__/|__/  |__/ \_______/ \_______/|__/      
| $$                    | $$                                                            
| $$                    | $$                                                            
|__/                    |__/                                                            


    """
    print(banner)


def main():
    print_banner()  
    
    if len(sys.argv) < 2:
        print("Please provide a domain name.")
        sys.exit(1)

    domain = sys.argv[1]

    # Program kapanmaya çalıştığında SIGINT sinyalini yakala
    scanner = SubdomainScanner(domain)
    signal.signal(signal.SIGINT, scanner.handle_interrupt)

    # Amass taramasını başlat
    scanner.amass_scan()

    # Amass çıktısını dosyadan alıp subdomain'leri ayıkla
    subdomains = scanner.extract_subdomains_from_file()

    # Subdomain'leri ekrana yazdır
    scanner.display_subdomains(subdomains)

    # Httprobe ile aktif HTTP(S) subdomain'lerini kontrol et
    http_subdomains = scanner.run_httprobe(list(subdomains))

    # HTTP(S) subdomain'lerini ekrana yazdır
    scanner.display_http_subdomains(http_subdomains)

    scanner.generate_github_dorks(domain)

    # Sonuçları report klasörüne kaydet
    scanner.save_to_report(subdomains, http_subdomains)

    # Amass output dosyasını sil
    scanner.remove_amass_output()



if __name__ == "__main__":
    main()

