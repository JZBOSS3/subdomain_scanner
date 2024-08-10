import sys
import subprocess
from colorama import Fore, Style

verbose = False
write = False
outFile = ''

vulnerable = [
    'elasticbeanstalk.com',
    's3.amazonaws.com',
    'agilecrm.com',
    'airee.ru',
    'animaapp.io',
    'bitbucket.io',
    'trydiscourse.com',
    'frontify',
    'furyns.com',
    'getresponse',
    'digital ocean', 'digitalocean', 'digital.ocean',
    'canny',
    'cargo collective', 'cargocollective', 'cargo.collective',
    'campaign monitor', 'campainmonitor', 'campain.monitor',
    'ghost.io',
    'github',
    'hatenablog.com',
    'helpjuice.com',
    'helpscoutdocs.com',
    'helprace.com',
    'heroku',
    'intercom',
    'youtrack.cloud',
    'landingi',
    'launchrock.com',
    'mashery',
    'cloudapp.net', 'cloudapp.azure.com', 'azurewebsites.net', 'blob.core.windows.net', 'cloudapp.azure.com', 'azure-api.net', 'azurehdinsight.net', 'azureedge.net', 'azurecontainer.io', 'database.windows.net', 'azuredatalakestore.net', 'search.windows.net', 'azurecr.io', 'redis.cache.windows.net', 'azurehdinsight.net', 'servicebus.windows.net', 'visualstudio.com',
    'netlify',
    'ngrok.io',
    'pantheon',
    'pingdom',
    'readme.io',
    'readthedocs',
    'shopify',
    'short.io',
    'smartjobboard',
    'Smartling',
    'Smugsmug',
    's.strikinglydns.com',
    'na-west1.surge.sh',
    'surveysparrow.com',
    'tilda',
    'tumblr',
    'read.uberflip.com',
    'stats.uptimerobot.com',
    'vercel',
    'webflow',
    'wix',
    'wordpress.com',
    'worksites.net'
]

def print_ascii():
    ascii_text = r"""
                                |     |
                                \\_V_//
                                \/=|=\/
                                 [=v=]
                               __\___/_____
                              /..[  _____  ]
                             /_  [ [  M /] ]
                            /../.[ [ M /@] ]
                           <-->[_[ [M /@/] ]
                          /../ [.[ [ /@/ ] ]
     _________________]\ /__/  [_[ [/@/ C] ]
    <_________________>>0---]  [=\ \@/ C / /
       ___      ___   ]/000o   /__\ \ C / /
          \    /              /....\ \_/ /
       ....\||/....           [___/=\___/
      .    .  .    .          [...] [...]
     .      ..      .         [___/ \___]
     .    0 .. 0    .         <---> <--->
  /\/\.    .  .    ./\/\      [..]   [..]
 / / / .../|  |\... \ \ \    _[__]   [__]_
/ / /       \/       \ \ \  [____>   <____]
"""
    print(Fore.GREEN + ascii_text + Style.RESET_ALL)
    print(Fore.CYAN + '\tSubdomain TakeOver Scanner' + Style.RESET_ALL)
    print(Fore.GREEN + '\tDeveloped By jzboss3' + Style.RESET_ALL)

def print_banner():
    print(Fore.LIGHTBLACK_EX + '*'*50 + Style.RESET_ALL)
    print(Fore.BLUE + '-h\tPrint Help and Exit' + Style.RESET_ALL)
    print(Fore.BLUE + '-u\tSpecify a Subdomain to Scan' + Style.RESET_ALL)
    print(Fore.BLUE + '-f\tSpecify a File of Subdomains to Scan' + Style.RESET_ALL)
    print(Fore.BLUE + '-o\tSpecify Output File' + Style.RESET_ALL)
    print(Fore.BLUE + '-v\tVerbose Mode' + Style.RESET_ALL)
    print(Fore.BLUE + '-e\tShow Usage Examples and Exit' + Style.RESET_ALL)
    print('Syntax: python vuln_subdomain.py <option> <value>')
    print(Fore.RED + 'More Info? Refer to:\nhttps://github.com/EdOverflow/can-i-take-over-xyz' + Style.RESET_ALL)
    print(Fore.LIGHTBLACK_EX + '*'*50 + Style.RESET_ALL)

def show_examples():
    print(Fore.LIGHTBLACK_EX + '*' * 50 + Style.RESET_ALL)
    print('python vuln_subdomain.py -u auth.example.com')
    print('python vuln_subdomain.py -f subdomains.txt')
    print('python vuln_subdomain.py -u auth.example.com -v')
    print('python vuln_subdomain.py -f subdomains.txt -o output.txt')
    print(Fore.LIGHTBLACK_EX + '*' * 50 + Style.RESET_ALL)

def write_to_file(state, url, cname):
    try:
        with open(outFile, mode='a') as file:
            file.write(f'State: {state}\n')
            file.write(f'Url: {url}\n')
            file.write(f'CNAME: {cname}\n')
            file.write('\n')
    except Exception:
        print(Fore.RED + f'Something Happened While Writing to File {outFile}' + Style.RESET_ALL)

def process_url(url):
    if 'http://' in url or 'https://' in url:
        url = url.split('://')[1]
    
    # Run the dig command
    dig_result = subprocess.run(['dig', url], capture_output=True, text=True)
    
    # Use subprocess to filter the result with grep
    grep_result = subprocess.run(['grep', 'CNAME'], input=dig_result.stdout, capture_output=True, text=True)
    
    # Save the filtered output
    filtered_output = grep_result.stdout
    
    if not filtered_output.strip():
        if verbose:
            print(Fore.CYAN + '[Not Vulnerable]' + Style.RESET_ALL)
            print(f'Url: {url}')
            print('CNAME: None')
            if write:
                write_to_file('[Not Vulnerable]', url, 'None')
            return
    
    try:
        output = filtered_output.split()
        if len(output) < 3:
            if verbose:
                raise IndexError("Filtered output does not have enough parts")
        
        cname = output[output.index('CNAME') + 1]

        vuln = any(service in cname for service in vulnerable)
        
        if vuln:
            print(Fore.RED + '[Vulnerable]' + Style.RESET_ALL)
            print(f'Url: {url}')
            print(f'CNAME: {cname}')
            if write:
                write_to_file('[Vulnerable]', url, cname)
        else:
            if verbose:
                print(Fore.CYAN + '[Not Vulnerable]' + Style.RESET_ALL)
                print(f'Url: {url}')
                print(f'CNAME: {cname}')
                if write:
                    write_to_file('[Not Vulnerable]', url, cname)
    except Exception as e:
        if verbose:
            print(Fore.RED + '[Error]' + Style.RESET_ALL)
            print(f'Url: {url}')
            print(f'Error: {e}')
            if write:
                write_to_file('[Error]', url, e)

def run_tool():
    args = sys.argv
    if len(args) < 2:
        print_banner()
        sys.exit()
    if len(args) == 2:
        for i in args:
            if i == '-e':
                show_examples()
            elif i == '-h':
                print_banner()
        sys.exit()
    else:
        global verbose, write, outFile
        for i in args:
            if i == '-v':
                verbose = True
            elif i == '-u' or i == '-f':
                flag = i
            elif i == '-o':
                write = True
                index = args.index(i)
                outFile = args[index + 1]
        if flag == '-u':
            url = args[2]
            verbose = True
            print(Fore.LIGHTBLACK_EX + '*' * 50 + Style.RESET_ALL)
            process_url(url)
            print(Fore.LIGHTBLACK_EX + '*' * 50 + Style.RESET_ALL)
        elif flag == '-f':
            urls_file = args[args.index(flag) + 1]
            try:
                with open(urls_file, 'r') as file:
                    for line in file:
                        url = line.strip()
                        process_url(url)
            except Exception as e:
                print(Fore.RED + '[File Error]' + Style.RESET_ALL)
                print(f'Something happened while reading the file: {e}')

if __name__ == "__main__":
    try:
        print_ascii()
        run_tool()
    except KeyboardInterrupt:
        print(Fore.RED + '\nCtrl+C Detected. Exiting...' + Style.RESET_ALL)
