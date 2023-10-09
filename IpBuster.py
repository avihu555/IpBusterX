import requests
import json
import subprocess



ip = input('\nWhat is the IP: ')
##Enter AbuseIPDB api key
#Insert API key here -------------------->
AbuseIPDB_api_key = '' 

##Enter virus total api key
#Insert API key here -------------------->
vt_api_key = ""


def AbuseIPDB(ip): # Abuseipdb api 
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': AbuseIPDB_api_key
    }
    response = requests.request(method='GET', url=url, headers=headers, params=querystring)
    
    decodedResponse = json.loads(response.text)
    # print(json.dumps(decodedResponse, sort_keys=True, indent=4))
    return decodedResponse

def abuseipdb_filter(decodedResponse): #Abuseipdb_parser
    if len(decodedResponse['data']['hostnames']) == 0:
        hosts = 'None'
    else:
        hosts = decodedResponse['data']['hostnames']
    
    return decodedResponse['data']['countryCode'],decodedResponse['data']['ipAddress'],decodedResponse['data']['isp'],decodedResponse['data']['domain'],hosts
       
    
def OTXAlienVault(ip): #OTX API return malicius or not with num of reports
       out = subprocess.run(f'python3 is_malicious.py -ip {ip}',capture_output=True,text=True)
       otx_out = out.stdout.replace('\n','')
       return otx_out
   
def VirusTotal(ip): #VT api 
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "accept": "application/json",
        "x-apikey": vt_api_key
    }
    response = requests.get(url, headers=headers)
    vt_decode = json.loads(response.text)
    
    return vt_decode

def VirousTotal_preser(vt_decode): # VT parser
    
    whoami = vt_decode['data']['attributes']['whois'] 
    malicius = vt_decode['data']['attributes']['last_analysis_stats']
    vt_lar = vt_decode['data']['attributes']['last_analysis_results']
    
    return whoami,malicius, vt_lar

    
def malicious_check(decodedResponse,otx_out,vt_malicius): # Check for intensity of threat  
    if decodedResponse['data']['abuseConfidenceScore'] >= 90 and 'Identified as potentially malicious' in otx_out and vt_malicius['malicious'] > 1:
        return "MALICIOUS ADDRESS!!!"
    
    elif 'Identified as potentially malicious' in otx_out or 0 < decodedResponse['data']['abuseConfidenceScore'] < 100 or decodedResponse['data']['lastReportedAt'] != None or (vt_malicius['suspicious'] != 0 and vt_malicius['undetected'] < 30):
        return 'Potentiall malicious address' 
    
    elif decodedResponse['data']['abuseConfidenceScore'] == 0 and 'Unknown or not identified as malicious' in otx_out and vt_malicius['malicious'] == 0 and vt_malicius['malicious'] == 0 and vt_malicius['suspicious'] == 0: 
        return 'This IP NOT reported as malicious!'
    
    else:
        return 'No data'
    
        
def data_show(country,ip_add, isp, domain, users,malicious_check,vt_whoami): #print data
    if vt_whoami == ' \n':
        vt_whoami = 'No whoami info'
    else:
        pass
    
    
    return f"\nCountry: {country}\nIP: {ip_add}\nISP: {isp}\nDomain: {domain}\nKnown users: {users}\nConclusion: {malicious_check}\n\nWHOAMI:\n{ vt_whoami}\n\n"    
       
def main():
    # 3 API engins check
    abuseipdb =  AbuseIPDB(ip)
    otx_out = OTXAlienVault(ip)
    vt = VirusTotal(ip) 
    
    # Persers
    country, ip_add, isp, domain, users =  abuseipdb_filter(abuseipdb)
    vt_whoami, vt_malicius, vt_lar = VirousTotal_preser(vt)
    
    # Check for intensity of threat
    mal_check = malicious_check(abuseipdb,otx_out,vt_malicius)
    
    
    # Print the data
    print(data_show(country, ip_add, isp, domain, users,mal_check,vt_whoami))
    
main()