import re
import sys
import subprocess
import signal
import os
import argparse



class HelpParser:
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            description="PMPFinder: A tool for subdomain enumeration using various tools like subfinder, assetfinder, amass, and bruteforce."
        )

        # Argumentleri tanımla
        self.parser.add_argument(
            "domain", type=str, help="Target domain for subdomain enumeration."
        )
        self.parser.add_argument(
            "--type",
            type=str,
            help="Comma separated list of tools to use (e.g., 'subfinder,assetfinder,amass').",
            required=True,
        )
        self.parser.add_argument(
            "--bruteforce", action="store_true", help="Run bruteforce subdomain enumeration."
        )
        self.parser.add_argument(
            "-w", type=str, default="resolvers/min-sub.txt", help="Wordlist for bruteforce (default: resolvers/min-sub.txt)."
        )
        self.parser.add_argument(
            "--rate-limit", type=str, default="100", help="Rate limit for bruteforce (default: 100)."
        )
        self.parser.add_argument(
            "--rate-limit-trusted", type=str, default="500", help="Rate limit for trusted domains (default: 500)."
        )
        self.parser.add_argument(
            "--onefile", action="store_true", help="Merge and save results into a single file."
        )
        self.parser.add_argument(
            "--http-mode", action="store_true", help="Enable HTTP mode for probing subdomains."
        )

    def print_help_examples(self):
        print("\nExamples:")
        print("1. Run with subdomain enumeration tools (subfinder, assetfinder, amass) and bruteforce:\n")
        print("   python pmpfinder.py teslamotors.com --type subfinder,assetfinder,amass --bruteforce -w resolvers/output_part_1.txt --rate-limit 100 --rate-limit-trusted 500 --onefile\n")
        print("2. Run with subdomain enumeration tools (subfinder, assetfinder) without bruteforce:\n")
        print("   python pmpfinder.py teslamotors.com --type subfinder,assetfinder\n")
        print("3. Run with subdomain enumeration tools (subfinder, amass) and bruteforce:\n")
        print("   python pmpfinder.py teslamotors.com --type subfinder,amass --bruteforce -w resolvers/output_part_1.txt --rate-limit 100 --rate-limit-trusted 500\n")
        print("4. Run with bruteforce only (without any other tools):\n")
        print("   python pmpfinder.py teslamotors.com --bruteforce -w resolvers/output_part_1.txt --rate-limit 100 --rate-limit-trusted 500\n")


    def parse_args(self):
        self.print_help_examples()
        return self.parser.parse_args()


class SubdomainScanner:
    def __init__(self, domain, tools=None):
        self.domain = domain
        self.tools = tools.split(",") if isinstance(tools, str) else tools or [] # Araçları listeye dönüştür
        self.process = None
        self.output_files = {
            "amass": f"{domain}_amass",
            "subfinder": f"{domain}_subfinder",
            "assetfinder": f"{domain}_assetfinder",
            "puredns": f"{domain}_puredns"
        }
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


    def run_subfinder(self, command, output_file):

        """Belirtilen komutu çalıştırır, çıktıyı sadece komutla yönlendirir."""
        try:
            print(f"Running command: {' '.join(command)}")
            # Komutu çalıştır ve konsol çıktısını kullan
            self.process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.process.wait()
            print(f"Command finished: {' '.join(command)}")
        except Exception as e:
            print(f"An error occurred while running command: {str(e)}")


    def subfinder_scan(self):
        """Subfinder taraması."""
        print("*****************************Starting subfinder Scanning*************************************")
        subfinder_command = [
            "subfinder",
            "-d", self.domain,
            "-o", os.path.join(self.report_dir, f"{self.output_files['subfinder']}_subdomains.txt")
        ]
        self.run_subfinder(subfinder_command, self.output_files["subfinder"])

    def assetfinder_scan(self):
        """Assetfinder taraması."""
        print("*****************************Starting assetfinder Scanning*************************************")

        assetfinder_command = ["assetfinder", "--subs-only", self.domain]
        #output_file = self.output_files["assetfinder"]
        output_file = os.path.join(self.report_dir, f"{self.domain}_assetfinder_subdomains.txt")
        try:
            with open(output_file, "w") as file:
                self.process = subprocess.Popen(assetfinder_command, stdout=file, stderr=subprocess.PIPE)
                self.process.wait()
            print(f"Results saved in {output_file}")
        except Exception as e:
            print(f"An error occurred while running assetfinder: {str(e)}")

    def puredns_bruteforce(self, rate_limit, rate_limit_trusted,wordlist):
        """Puredns brute-force taraması."""
        print("***************************** Starting PureDNS Bruteforce *************************************")
        try:
            # Dosya adını domain'e göre oluştur
            output_file = os.path.join(
                self.report_dir,
                f"{self.output_files['puredns']}_subdomains.txt"
            )
            
            # Puredns komutunu hazırla
            puredns_command = [
            "./puredns", "bruteforce", wordlist, self.domain,
            "--rate-limit", rate_limit,
            "--rate-limit-trusted", rate_limit_trusted,
            "--write", output_file
            ]
            
            print(f"Running command: {' '.join(puredns_command)}")
            self.process = subprocess.Popen(puredns_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = self.process.communicate()

            if self.process.returncode == 0:
                print(f"PureDNS Brute-Force completed. Results saved in {output_file}")
            else:
                print(f"PureDNS Brute-Force failed with error:\n{stderr.decode()}")
        except Exception as e:
            print(f"An error occurred while running PureDNS: {str(e)}")


    def amass_scan(self):
        """Amass taramasını çalıştırır ve çıktıyı dosyaya kaydeder."""
        print("*****************************Starting amass Scanning*************************************")
        try:
            print(f"Scanning the domain {self.domain}...")
            amass_command = ["amass", "enum", "-d", self.domain, "-o", self.output_files['amass']]
            self.process = subprocess.Popen(amass_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Çıktıyı okur ve dosyaya yazar, süreç devam ettiği sürece
            with open(self.output_files['amass'], "a") as file:
                while self.process.poll() is None:  
                    output = self.process.stdout.readline()  
                    if output:
                        file.write(output.decode())  
                self.process.wait()  
            print(f"Scan complete. Results saved in {self.output_files['amass']}.")
        except Exception as e:
            print(f"An error occurred: {str(e)}")
    def amass_full_exec(self):

        self.amass_scan()
        # Amass çıktısını dosyadan alıp subdomain'leri ayıkla
        subdomains = self.extract_amass_subdomains_from_file()

        # Subdomain'leri ekrana yazdır
        self.display_subdomains_amass(subdomains)

        # Httprobe ile aktif HTTP(S) subdomain'lerini kontrol et
        #http_subdomains = self.run_httprobe(list(subdomains))

        # HTTP(S) subdomain'lerini ekrana yazdır
        #self.display_http_amass_subdomains(http_subdomains)

        file_process.amass_save_to_report(self.domain,subdomains)



    def extract_amass_subdomains_from_file(self):
        """Amass çıktısındaki subdomain'leri ayıklar."""
        try:
            with open(self.output_files["amass"], "r") as file:
                data = file.readlines()

            subdomains = set()
            for line in data:
                match = re.search(r'\b([a-zA-Z0-9.-]+\.' + re.escape(self.domain) + r'\b)', line)
                if match:
                    subdomains.add(match.group(1))

            return sorted(subdomains)
        except FileNotFoundError:
            print(f"File not found: {self.output_files['amass']}")
            return []


    def display_subdomains_amass(self, subdomains):
        
        if subdomains:
            print(f"\nSubdomains found for {self.domain}:")
            for subdomain in subdomains:
                print(subdomain)
        else:
            print(f"No subdomains found for {self.domain}.")

    def display_http_amass_subdomains(self, http_subdomains):
        """Aktif HTTP(S) subdomain'leri ekrana yazdırır."""
        if http_subdomains:
            print("\n[INFO] Active HTTP(S) subdomains:")
            for sub in http_subdomains:
                print(sub)
        else:
            print("[INFO] No active HTTP(S) subdomains found.")
        print("++++++++++++++++++ showing amass subdomains +++++++++++++++++++++")


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


class file_process:
    def __init__(self, domain):

        self.create_report_directory()

    def create_report_directory(self):
        """'report' klasörünü oluşturur."""
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)
    @staticmethod
    def merge_unique_subdomains(domain,output_file,report_dir = "report"):
        """
        Merges subdomains from files that start with the given domain and end with '_subdomains.txt'.
        Writes unique and sorted subdomains to the specified output file.
        """
        unique_subdomains = set()
        
        # Filter files: must start with the domain and end with '_subdomains.txt'
        txt_files = [
            f for f in os.listdir(report_dir)
            if f.startswith(f"{domain}_") and f.endswith('_subdomains.txt')
        ]

        # Read each file and collect subdomains
        for file in txt_files:
            file_path = os.path.join(report_dir, file)
            try:
                with open(file_path, 'r') as f:
                    # Normalize lines: strip whitespace and remove empty lines
                    unique_subdomains.update(line.strip() for line in f.read().splitlines() if line.strip())
                print(f"[INFO] Subdomains from '{file}' have been read.")
            except FileNotFoundError:
                print(f"[ERROR] File '{file}' not found.")

        # Write unique subdomains to the output file
        with open(output_file, 'w') as output:
            output.write('\n'.join(sorted(unique_subdomains)))

        print(f"[INFO] Unique subdomains have been written to '{output_file}'.")

    @staticmethod
    def amass_save_to_report(domain,subdomains,report_dir = "report"):
        """Sonuçları 'report' klasörüne kaydeder."""
        # Subdomain'leri dosyaya kaydet
        subdomains_file = os.path.join(report_dir, f"{domain}_amass_subdomains.txt")
        with open(subdomains_file, "w") as file:
            for subdomain in subdomains:
                file.write(f"{subdomain}\n")
        print(f"Subdomains saved to {subdomains_file}.")


    @staticmethod
    def remove_amass_output(domain):

        output_file = domain+"_amass"
        """Temp Amass output dosyasını siler."""
        if os.path.exists(output_file):
            os.remove(output_file)
            print(f"{output_file} has been removed.")


class port_scanner:

    def __init__(self, domain):
        self.report_dir = "report"
        self.domain = domain

    def read_and_save_http_sub(self):
        # http_sub klasörünü oluştur
        http_sub_dir = os.path.join(self.report_dir, "http_sub")
        os.makedirs(http_sub_dir, exist_ok=True)

        # Rapor klasöründen dosyaları filtrele
        txt_files = [
            f for f in os.listdir(self.report_dir)
            if f.startswith(f"{self.domain}_") and f.endswith('_subdomains.txt')
        ]

        # Her bir dosya için işlemleri gerçekleştir
        for txt_file in txt_files:
            # _subdomains.txt ifadesini _http_subdomains.txt olarak değiştir
            output_file = os.path.join(http_sub_dir, txt_file.replace('_subdomains.txt', '_http_subdomains.txt'))
            file_path = os.path.join(self.report_dir, txt_file)
            
            try:
                # Subdomain'leri oku
                with open(file_path, "r") as file:
                    subdomains = [line.strip() for line in file if line.strip()]
                
                # Subdomain'ler için httprobe çalıştır
                active_subdomains = self.run_httprobe(subdomains)
                
                # Sonuçları kaydet
                with open(output_file, "w") as out_file:
                    out_file.write("\n".join(active_subdomains))
                
                print(f"[INFO] Results saved to {output_file}")
            except FileNotFoundError:
                print(f"[ERROR] File not found: {file_path}")
            except Exception as e:
                print(f"[ERROR] An error occurred: {str(e)}")


    def run_httprobe(self, subdomains):
        """Subdomain'leri kontrol etmek için httprobe çalıştırır."""
        print("\n[INFO] Starting HTTP probe...")
        try:
            process = subprocess.Popen(
                ['httprobe'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout, stderr = process.communicate(input="\n".join(subdomains).encode())
            if process.returncode == 0:
                return stdout.decode().splitlines()
            else:
                print(f"[ERROR] httprobe failed with error: {stderr.decode()}")
                return []
        except Exception as e:
            print(f"[ERROR] An error occurred while running httprobe: {str(e)}")
            return []




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


    print("Welcome to PMPFinder!")

    help_parser = HelpParser()
    args = help_parser.parse_args()
    
    if len(sys.argv) < 3:
        print("Usage: python pmpfinder.py <domain> --type <tools> [--onefile]")
        print("Example: python pmpfinder.py example.com --type amass,subfinder,assetfinder,gitdork --onefile")
        sys.exit(1)

    domain = sys.argv[1]
    # --type veya --bruteforce parametresi olmadan işlem yapılamaz
    if "--type" not in sys.argv and "--bruteforce" not in sys.argv:
        print("Please specify the tools using --type (e.g., amass,subfinder,assetfinder,gitdork).")
        sys.exit(1)

    scanner = None  # scanner nesnesi burada tanımlanıyor

    # --type parametresi varsa, araçları ayarla
    if "--type" in sys.argv:
        tools = sys.argv[sys.argv.index("--type") + 1].split(',')
        scanner = SubdomainScanner(domain, tools)
        signal.signal(signal.SIGINT, scanner.handle_interrupt)

        ######
        # Seçilen araçları çalıştır
        if "subfinder" in scanner.tools:
            scanner.subfinder_scan()
        if "assetfinder" in scanner.tools:
            scanner.assetfinder_scan()
        if "gitdork" in scanner.tools:
            scanner.generate_github_dorks(domain)
        if "amass" in scanner.tools:
            scanner.amass_full_exec()
            
    # Eğer scanner yoksa ve --bruteforce parametresi varsa, scanner nesnesi oluştur
    if "--bruteforce" in sys.argv and scanner is None:
        scanner = SubdomainScanner(domain)

    # --bruteforce parametresi varsa, bruteforce işlemini gerçekleştir
    if "--bruteforce" in sys.argv:
        rate_limit = "100"
        rate_limit_trusted = "500"
        wordlist = "resolvers/min-sub.txt"  # Varsayılan wordlist dosyası
        
        # "--rate-limit" ve "--rate-limit-trusted" parametrelerini kontrol et
        if "--rate-limit" in sys.argv:
            rate_limit = sys.argv[sys.argv.index("--rate-limit") + 1]
        if "--rate-limit-trusted" in sys.argv:
            rate_limit_trusted = sys.argv[sys.argv.index("--rate-limit-trusted") + 1]

        # "-w" parametresini kontrol et ve wordlist dosyasını ayarla
        if "-w" in sys.argv:
            wordlist = sys.argv[sys.argv.index("-w") + 1]

        # Puredns bruteforce fonksiyonunu çalıştır
        scanner.puredns_bruteforce(rate_limit, rate_limit_trusted, wordlist)

    if "--onefile" in sys.argv:
        output_file = os.path.join(scanner.report_dir, f"{domain}_merged_subdomains.txt")

        file_process.merge_unique_subdomains(domain,output_file)
    
    # --onefile parametresi varsa, tüm subdomain'leri tek dosyaya birleştir
    if "--http-mode" in sys.argv:
        http_mode = port_scanner(domain)
        http_mode.read_and_save_http_sub()

    


    # Amass output dosyasını sil
    file_process.remove_amass_output(domain)



if __name__ == "__main__":
    main()

