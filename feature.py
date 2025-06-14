import re
import socket
import requests
from urllib.parse import urlparse
from datetime import date
from bs4 import BeautifulSoup
import whois
import urllib.request
from googlesearch import search

class FeatureExtraction:
    def __init__(self, url):
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = None
        self.urlparse_obj = None
        self.response = None
        self.soup = None
        
        # Attempt to request the URL and parse the HTML
        try:
            self.response = requests.get(url, timeout=10)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except Exception:
            pass
        
        # Parse URL and extract domain
        try:
            self.urlparse_obj = urlparse(url)
            self.domain = self.urlparse_obj.netloc
        except Exception:
            pass
        
        # Get WHOIS information for the domain
        try:
            self.whois_response = whois.whois(self.domain)
        except Exception:
            self.whois_response = None
        
        # Append 30 features (order must match the model’s training)
        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Https())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())
        self.features.append(self.NonStdPort())
        self.features.append(self.HTTPSDomainURL())
        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.InfoEmail())
        self.features.append(self.AbnormalURL())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.StatusBarCust())
        self.features.append(self.DisableRightClick())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.IframeRedirection())
        self.features.append(self.AgeofDomain())
        self.features.append(self.DNSRecording())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.PageRank())
        self.features.append(self.GoogleIndex())
        self.features.append(self.LinksPointingToPage())
        self.features.append(self.StatsReport())

    # 1. Using IP address in URL
    def UsingIp(self):
        try:
            # If the URL is an IP address, return -1; otherwise, 1.
            socket.inet_aton(self.url)
            return -1
        except Exception:
            return 1

    # 2. Long URL
    def longUrl(self):
        if len(self.url) < 60:
            return 1
        elif 60 <= len(self.url) <= 100:
            return 0
        return -1

    # 3. Short URL (using known URL shorteners)
    def shortUrl(self):
        if re.search(r'bit\.ly|goo\.gl|shorte\.st|tinyurl', self.url):
            return -1
        return 1

    # 4. Symbol '@' in URL
    def symbol(self):
        if "@" in self.url:
            return -1
        return 1

    # 5. Double slashes after the protocol
    def redirecting(self):
        pos = self.url.find("//", self.url.find("://") + 3) if "://" in self.url else -1
        if pos != -1:
            return -1
        return 1

    # 6. Hyphen in the domain
    def prefixSuffix(self):
        if "-" in self.domain:
            return -1
        return 1

    # 7. Count of subdomains (based on dots in the domain)
    def SubDomains(self):
        dot_count = self.domain.count(".")
        if dot_count == 1:
            return 1
        elif dot_count == 2:
            return 0
        return -1

    # 8. Check for HTTPS
    def Https(self):
        if self.urlparse_obj and self.urlparse_obj.scheme.lower() == "https":
            return 1
        return -1

    # 9. Domain registration length (in months)
    def DomainRegLen(self):
        try:
            if self.whois_response:
                expiration_date = self.whois_response.expiration_date
                creation_date = self.whois_response.creation_date
                if isinstance(expiration_date, list):
                    expiration_date = expiration_date[0]
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                age_months = (expiration_date.year - creation_date.year) * 12 + (expiration_date.month - creation_date.month)
                if age_months >= 12:
                    return 1
            return -1
        except Exception:
            return -1

    # 10. Favicon
    def Favicon(self):
        try:
            if not self.soup:
                return -1
            head = self.soup.find("head")
            if head:
                for link in head.find_all("link", href=True):
                    href = link['href']
                    if self.url in href or self.domain in href:
                        return 1
            return -1
        except Exception:
            return -1

    # 11. Non-standard port usage
    def NonStdPort(self):
        if ":" in self.domain:
            return -1
        return 1

    # 12. HTTPS in the domain part of the URL
    def HTTPSDomainURL(self):
        if "https" in self.domain.lower():
            return -1
        return 1

    # 13. Request URL analysis for external resource links
    def RequestURL(self):
        try:
            if not self.soup:
                return -1
            total, valid = 0, 0
            for tag in ['img', 'audio', 'embed', 'iframe']:
                for element in self.soup.find_all(tag, src=True):
                    total += 1
                    src = element['src']
                    if self.url in src or self.domain in src:
                        valid += 1
            percentage = (valid / total * 100) if total else 0
            if percentage < 22.0:
                return 1
            elif 22.0 <= percentage < 61.0:
                return 0
            return -1
        except Exception:
            return -1

    # 14. Anchor URL analysis
    def AnchorURL(self):
        try:
            if not self.soup:
                return -1
            total, unsafe = 0, 0
            for a in self.soup.find_all('a', href=True):
                total += 1
                href = a['href']
                if ("#" in href) or ("javascript" in href.lower()) or ("mailto" in href.lower()) or (self.url not in href and self.domain not in href):
                    unsafe += 1
            percentage = (unsafe / total * 100) if total else 0
            if percentage < 31.0:
                return 1
            elif 31.0 <= percentage < 67.0:
                return 0
            return -1
        except Exception:
            return -1

    # 15. Links in script or link tags
    def LinksInScriptTags(self):
        try:
            if not self.soup:
                return -1
            total, valid = 0, 0
            for tag in ['link', 'script']:
                for element in self.soup.find_all(tag, src=True):
                    total += 1
                    src = element['src']
                    if self.url in src or self.domain in src:
                        valid += 1
            percentage = (valid / total * 100) if total else 0
            if percentage < 17.0:
                return 1
            elif 17.0 <= percentage < 81.0:
                return 0
            return -1
        except Exception:
            return -1

    # 16. Server form handler analysis
    def ServerFormHandler(self):
        try:
            if not self.soup:
                return -1
            for form in self.soup.find_all('form', action=True):
                action = form['action']
                if action == "" or action == "about:blank":
                    return -1
                elif self.url not in action and self.domain not in action:
                    return 0
                else:
                    return 1
            return 1
        except Exception:
            return -1

    # 17. Check for info email presence
    def InfoEmail(self):
        try:
            if self.soup and re.search(r"mailto:", self.soup.text):
                return -1
            else:
                return 1
        except Exception:
            return -1

    # 18. Abnormal URL (a simple check against WHOIS)
    def AbnormalURL(self):
        try:
            if self.response and self.whois_response and self.response.text in str(self.whois_response):
                return 1
            else:
                return -1
        except Exception:
            return -1

    # 19. Website forwarding (redirection history)
    def WebsiteForwarding(self):
        try:
            if self.response and len(self.response.history) <= 1:
                return 1
            elif self.response and len(self.response.history) <= 4:
                return 0
            else:
                return -1
        except Exception:
            return -1

    # 20. Status bar customization (onmouseover events in scripts)
    def StatusBarCust(self):
        try:
            if self.response and re.search(r"<script>.+onmouseover.+</script>", self.response.text):
                return 1
            else:
                return -1
        except Exception:
            return -1

    # 21. Disable right click check
    def DisableRightClick(self):
        try:
            if self.response and re.search(r"event.button\s*==\s*2", self.response.text):
                return 1
            else:
                return -1
        except Exception:
            return -1

    # 22. Using popup window
    def UsingPopupWindow(self):
        try:
            if self.response and re.search(r"alert\(", self.response.text):
                return 1
            else:
                return -1
        except Exception:
            return -1

    # 23. Iframe redirection check
    def IframeRedirection(self):
        try:
            if self.response and re.search(r"<iframe|<frameBorder", self.response.text):
                return 1
            else:
                return -1
        except Exception:
            return -1

    # 24. Age of domain
    def AgeofDomain(self):
        try:
            if self.whois_response:
                creation_date = self.whois_response.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                today = date.today()
                age_months = (today.year - creation_date.year) * 12 + (today.month - creation_date.month)
                if age_months >= 6:
                    return 1
            return -1
        except Exception:
            return -1

    # 25. DNS recording (using Age of Domain check)
    def DNSRecording(self):
        return self.AgeofDomain()

    # 26. Website traffic (using Alexa ranking)
    def WebsiteTraffic(self):
        try:
            url_ = "http://data.alexa.com/data?cli=10&dat=s&url=" + self.url
            xml_data = urllib.request.urlopen(url_).read()
            soup_xml = BeautifulSoup(xml_data, "xml")
            reach = soup_xml.find("REACH")
            if reach and "RANK" in reach.attrs:
                rank = int(reach["RANK"])
                if rank < 100000:
                    return 1
                else:
                    return 0
            return -1
        except Exception:
            return -1

    # 27. Page rank (via an online checker)
    def PageRank(self):
        try:
            response = requests.post("https://www.checkpagerank.net/index.php", data={"name": self.domain}, timeout=10)
            match = re.search(r"Global Rank:\s*([0-9]+)", response.text)
            if match:
                global_rank = int(match.group(1))
                if 0 < global_rank < 100000:
                    return 1
            return -1
        except Exception:
            return -1

    # 28. Google index check (using googlesearch)
    def GoogleIndex(self):
        try:
            results = list(search(self.url, num_results=5))
            if results:
                return 1
            else:
                return -1
        except Exception:
            return 1

    # 29. Links pointing to the page
    def LinksPointingToPage(self):
        try:
            if self.response:
                count = len(re.findall(r"<a\s+href=", self.response.text, re.IGNORECASE))
                if count == 0:
                    return 1
                elif count <= 2:
                    return 0
                else:
                    return -1
            return -1
        except Exception:
            return -1

    # 30. Stats report (compare URL/IP with known malicious patterns)
    def StatsReport(self):
        try:
            url_match = re.search(
                r'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly',
                self.url)
            ip_address = socket.gethostbyname(self.domain)
            ip_match = re.search(
                r'146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|'
                r'46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|107\.151\.148\.44|107\.151\.148\.107',
                ip_address)
            if url_match or ip_match:
                return -1
            return 1
        except Exception:
            return 1

    def getFeaturesList(self):
        return self.features
