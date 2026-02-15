import os
import re
import uuid
import logging
from typing import Dict, Any, List
from datetime import datetime
import json

# Initialize module logger
logger = logging.getLogger(__name__)

# --- PDF Dependency Integration (Placeholder) ---
try:
    from .pdf_extractor import extract_text_from_pdf
except ImportError:
    def extract_text_from_pdf(pdf_path: str) -> str:
        raise NotImplementedError("pdf_extractor.py not found.")

def clean_raw_text(text: str) -> str:
    """
    Aggressively cleans the text to handle PDF artifacts, footers, 
    and jammed text.
    """
    text = re.sub(r'\r\n|\r', '\n', text)
    text = re.sub(r'Page \d+ of \d+', '', text)
    
    # 1. Remove the ZAP footer that jams into titles
    text = re.sub(r'NETSHIELDAI.*?GENERATED \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', '\n', text, flags=re.DOTALL)
    
    # 2. Fix "Jammed" Risk Levels (e.g., "15HIGH" -> "15 HIGH")
    text = re.sub(r'([a-z0-9)])(HIGH|MEDIUM|LOW|INFO)', r'\1 \2', text)
    
    # 3. Fix "Jammed" URL/Score fields
    text = re.sub(r'([\d\w])(TARGET URL)', r'\1 \2', text)
    
    # 4. Ensure RISK is separated
    text = re.sub(r'([^\s])(HIGH|MEDIUM|LOW|INFO) RISK', r'\1 \2 RISK', text)

    return text

def extract_summary_stats(clean_text: str) -> Dict[str, int]:
    """
    Extracts the counts directly from the EXECUTIVE SUMMARY section.
    """
    stats = {
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0,
        "Total": 0
    }

    # Locate the Executive Summary block
    # Pattern looks for "TOTAL ALERTS" followed explicitly by the numbers
    # Because of cleaning, "15HIGH" becomes "15 HIGH"
    
    # 1. Extract TOTAL
    total_match = re.search(r"TOTAL ALERTS\s*(\d+)", clean_text, re.IGNORECASE)
    if total_match:
        stats["Total"] = int(total_match.group(1))

    # 2. Extract HIGH
    high_match = re.search(r"(\d+)\s*HIGH RISK", clean_text, re.IGNORECASE)
    if high_match:
        stats["High"] = int(high_match.group(1))

    # 3. Extract MEDIUM
    med_match = re.search(r"(\d+)\s*MEDIUM RISK", clean_text, re.IGNORECASE)
    if med_match:
        stats["Medium"] = int(med_match.group(1))

    # 4. Extract LOW / INFO
    # The report groups "LOW / INFO" with a single number usually, 
    # or lists them sequentially. In your specific text: "4LOW / INFO"
    # We will try to capture the number before "LOW"
    low_info_match = re.search(r"(\d+)\s*LOW\s*/\s*INFO", clean_text, re.IGNORECASE)
    if low_info_match:
        # If grouped, we might just assign to Low or split. 
        # For now, let's assign to Low to ensure it's captured.
        stats["Low"] = int(low_info_match.group(1))
        # Determine INFO separately if possible, or leave as 0 if grouped
    
    # Fallback: if specific risk counts are missing, we still rely on findings list for breakdown,
    # but we KEEP the explicit Total from the header.
    
    return stats

def parse_zap_report(raw_text: str) -> Dict[str, Any]:
    clean_text = clean_raw_text(raw_text)
    
    # --- STEP 1: Extract Stats from Header ---
    header_stats = extract_summary_stats(clean_text)
    
    findings_list = []

    # --- STEP 2: Parse Individual Findings ---
    confidence_markers = list(re.finditer(r"\nCONFIDENCE\s", clean_text))
    
    for i, marker in enumerate(confidence_markers):
        current_conf_start = marker.start()
        
        if i + 1 < len(confidence_markers):
            next_conf_start = confidence_markers[i+1].start()
            search_limit = next_conf_start
        else:
            search_limit = len(clean_text)

        # Backwards Search for Title
        pre_text_chunk = clean_text[max(0, current_conf_start-600):current_conf_start]
        lines = pre_text_chunk.split('\n')
        
        vuln_name = "Unknown Vulnerability"
        risk_level = "Unknown"
        
        for line in reversed(lines):
            line = line.strip()
            if not line: continue
            
            risk_match = re.search(r"(.*)\s+(HIGH|MEDIUM|LOW|INFO)\s+RISK$", line, re.IGNORECASE)
            
            if risk_match:
                possible_name = risk_match.group(1).strip()
                if len(possible_name) < 150:
                    vuln_name = possible_name
                    risk_level = risk_match.group(2).upper()
                    break
            
            if "REFERENCES" in line or "REMEDIATION SOLUTION" in line:
                break

        # Forwards Search for Body
        body_text = clean_text[marker.end():search_limit]
        
        conf_match = re.match(r"\s*([A-Za-z]+)", body_text)
        confidence = conf_match.group(1) if conf_match else "Unknown"

        score_match = re.search(r"PREDICTED SCORE\s*([\d\.]+|N/A)", body_text)
        score = score_match.group(1) if score_match else "N/A"

        url_match = re.search(r"TARGET URL\s*(.*?)DESCRIPTION", body_text, re.DOTALL)
        url = "Unknown"
        if url_match:
            url = url_match.group(1).replace('\n', '').replace(' ', '').strip()

        desc_match = re.search(r"DESCRIPTION(.*?)(REMEDIATION SOLUTION|SOLUTION)", body_text, re.DOTALL)
        description = desc_match.group(1).strip() if desc_match else ""

        sol_match = re.search(r"(REMEDIATION SOLUTION|SOLUTION)(.*?)REFERENCES", body_text, re.DOTALL)
        solution = sol_match.group(2).strip() if sol_match else ""

        refs = []
        ref_match = re.search(r"REFERENCES(.*)", body_text, re.DOTALL)
        if ref_match:
            ref_content = ref_match.group(1)
            lines_ref = ref_content.split('\n')
            for line in lines_ref:
                line = line.strip()
                if not line: continue
                if re.search(r"(HIGH|MEDIUM|LOW|INFO)\s+RISK$", line):
                    break
                if "http" in line or "owasp" in line.lower():
                    refs.append(line)

        findings_list.append({
            "name": vuln_name,
            "risk_level": risk_level,
            "confidence": confidence,
            "predicted_score": score,
            "url": url,
            "description": description,
            "solution": solution,
            "references": refs
        })

    # --- STEP 3: Reconcile Stats ---
    # We prioritize the Header Extracted Total ("15")
    # But we count the explicit findings for the breakdown if the header was ambiguous (like "Low/Info")
    
    final_stats = {
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0,
        "Total": header_stats["Total"] if header_stats["Total"] > 0 else 0
    }

    # Count breakdown from findings
    for finding in findings_list:
        # If we didn't find a Total in the header, we sum it up manually
        if final_stats["Total"] == 0:
             final_stats["Total"] += 1

        r_level = finding['risk_level'].title()
        if r_level in final_stats:
            final_stats[r_level] += 1

    report = {
        "scan_metadata": {
            "tool": "OWASP ZAP",
            "report_id": str(uuid.uuid4()),
            "generated_at": datetime.now().isoformat()
        },
        "alert_summary": final_stats,
        "findings": findings_list
    }

    return report

def process_zap_report_file(file_path: str) -> Dict[str, Any]:
    """
    Orchestrates reading the PDF, extracting text, and parsing the ZAP data.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"ZAP report not found: {file_path}")
    
    logger.info(f"Processing ZAP report: {file_path}")
    try:
        # Extract raw text using the PDF dependency
        raw_text = extract_text_from_pdf(file_path)
        
        if not raw_text.strip():
            raise ValueError("Extracted text from file is empty.")
            
        # Call the ZAP specific parser (Fixed from parse_nmap_report)
        report_data = parse_zap_report(raw_text)
        
        # Add file-level metadata
        report_data["file_metadata"] = {
            "filename": os.path.basename(file_path),
            "file_size": os.path.getsize(file_path),
            "last_modified": datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
        }
        return report_data
        
    except Exception as e:
        logger.error(f"Error processing ZAP report {file_path}: {e}")
        raise

# --- Testing Block ---
if __name__ == "__main__":
    # Test with the extracted text from your prompt
    test_text = """
Web Vulnerability
Report
// ZAP SECURITY ENGINE
EXECUTIVE SUMMARY
TOTAL ALERTS
15HIGH RISK
3MEDIUM RISK
4LOW / INFO
4
TARGET URL
http://
testphp.vulnweb.com/
artists.php?artist=1SCAN DATE
2026-01-07 16:28:49ENGINE
OWASP ZAP 2.15+
Page 1 of 15
DETAILED FINDINGS
SQL Injection - MySQL (Time Based) HIGH RISK
CONFIDENCE
Medium PREDICTED SCORE
15.48TARGET URL
http://testphp.vulnweb.com/artists.ph...
DESCRIPTION
SQL injection may be possible.
REMEDIATION SOLUTION
Do not trust client side input, even if there is client side validation in place.
In general, type check all data on the server side.
If the application uses JDBC, use PreparedStatement or CallableStatement, with parameters 
passed by '?'
If the application uses ASP, use ADO Command Objects with strong type checking and 
parameterized queries.
If database Stored Procedures can be used, use them.
Do *not* concatenate strings into queries in the stored procedure, or use 'exec', 'exec 
immediate', or equivalent functionality!
Do not create dynamic SQL queries using simple string concatenation.
Escape all data received from the client.
Apply an 'allow list' of allowed characters, or a 'deny list' of disallowed characters in 
user input.
Apply the principle of least privilege by using the least privileged database user 
possible.
In particular, avoid using the 'sa' or 'db-owner' database users. This does not eliminate 
SQL injection, but minimizes its impact.
Grant the minimum database access that is necessary for the application.
REFERENCES
https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
Page 2 of 15
Cross Site Scripting (Reflected) HIGH RISK
CONFIDENCE
Medium PREDICTED SCORE
9.53TARGET URL
http://testphp.vulnweb.com/artists.ph...
DESCRIPTION
Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied 
code into a user's browser instance. A browser instance can be a standard web browser 
client, or a browser object embedded in a software product such as the browser within 
WinAmp, an RSS reader, or an email client. The code itself is usually written in HTML/
JavaScript, but may also extend to VBScript, ActiveX, Java, Flash, or any other browser-
supported technology.
When an attacker gets a user's browser to execute his/her code, the code will run within 
the security context (or zone) of the hosting web site. With this level of privilege, the 
code has the ability to read, modify and transmit any sensitive data accessible by the 
browser. A Cross-site Scripted user could have his/her account hijacked (cookie theft), 
their browser redirected to another location, or possibly shown fraudulent content 
delivered by the web site they are visiting. Cross-site Scripting attacks essentially 
compromise the trust relationship between a user and the web site. Applications utilizing 
browser object instances which load content from the file system may execute code under the 
local machine zone allowing for system compromise.
There are three types of Cross-site Scripting attacks: non-persistent, persistent and DOM-
based.
Non-persistent attacks and DOM-based attacks require a user to either visit a specially 
crafted link laced with malicious code, or visit a malicious web page containing a web 
form, which when posted to the vulnerable site, will mount the attack. Using a malicious 
form will oftentimes take place when the vulnerable resource only accepts HTTP POST 
requests. In such a case, the form can be submitted automatically, without the victim's 
knowledge (e.g. by using JavaScript). Upon clicking on the malicious link or submitting the 
malicious form, the XSS payload will get echoed back and will get interpreted by the user's 
browser and execute. Another technique to send almost arbitrary requests (GET and POST) is 
by using an embedded client, such as Adobe Flash.
Persistent attacks occur when the malicious code is submitted to a web site where it's 
stored for a period of time. Examples of an attacker's favorite targets often include 
message board posts, web mail messages, and web chat software. The unsuspecting user is not 
required to interact with any additional site/link (e.g. an attacker site or a malicious 
link sent via email), just simply view the web page containing the code.
REMEDIATION SOLUTION
Phase: Architecture and Design
Use a vetted library or framework that does not allow this weakness to occur or provides 
constructs that make this weakness easier to avoid.
Examples of libraries and frameworks that make it easier to generate properly encoded 
output include Microsoft's Anti-XSS library, the OWASP ESAPI Encoding module, and Apache 
Wicket.
Phases: Implementation; Architecture and Design
Page 3 of 15
Understand the context in which your data will be used and the encoding that will be 
expected. This is especially important when transmitting data between different components, 
or when generating outputs that can contain multiple encodings at the same time, such as 
web pages or multi-part mail messages. Study all expected communication protocols and data 
representations to determine the required encoding strategies.
For any data that will be output to another web page, especially any data that was received 
from external inputs, use the appropriate encoding on all non-alphanumeric characters.
Consult the XSS Prevention Cheat Sheet for more details on the types of encoding and 
escaping that are needed.
Phase: Architecture and Design
For any security checks that are performed on the client side, ensure that these checks are 
duplicated on the server side, in order to avoid CWE-602. Attackers can bypass the client-
side checks by modifying values after the checks have been performed, or by changing the 
client to remove the client-side checks entirely. Then, these modified values would be 
submitted to the server.
If available, use structured mechanisms that automatically enforce the separation between 
data and code. These mechanisms may be able to provide the relevant quoting, encoding, and 
validation automatically, instead of relying on the developer to provide this capability at 
every point where output is generated.
Phase: Implementation
For every web page that is generated, use and specify a character encoding such as 
ISO-8859-1 or UTF-8. When an encoding is not specified, the web browser may choose a 
different encoding by guessing which encoding is actually being used by the web page. This 
can cause the web browser to treat certain sequences as special, opening up the client to 
subtle XSS attacks. See CWE-116 for more mitigations related to encoding/escaping.
To help mitigate XSS attacks against the user's session cookie, set the session cookie to 
be HttpOnly. In browsers that support the HttpOnly feature (such as more recent versions of 
Internet Explorer and Firefox), this attribute can prevent the user's session cookie from 
being accessible to malicious client-side scripts that use document.cookie. This is not a 
complete solution, since HttpOnly is not supported by all browsers. More importantly, 
XMLHTTPRequest and other powerful browser technologies provide read access to HTTP headers, 
including the Set-Cookie header in which the HttpOnly flag is set.
Assume all input is malicious. Use an "accept known good" input validation strategy, i.e., 
use an allow list of acceptable inputs that strictly conform to specifications. Reject any 
input that does not strictly conform to specifications, or transform it into something that 
does. Do not rely exclusively on looking for malicious or malformed inputs (i.e., do not 
rely on a deny list). However, deny lists can be useful for detecting potential attacks or 
determining which inputs are so malformed that they should be rejected outright.
When performing input validation, consider all potentially relevant properties, including 
length, type of input, the full range of acceptable values, missing or extra inputs, 
syntax, consistency across related fields, and conformance to business rules. As an example 
of business rule logic, "boat" may be syntactically valid because it only contains 
alphanumeric characters, but it is not valid if you are expecting colors such as "red" or 
"blue."
Ensure that you perform input validation at well-defined interfaces within the application. 
This will help protect the application even if a component is reused or moved elsewhere.
Page 4 of 15
REFERENCES
https://owasp.org/www-community/attacks/xss/
https://cwe.mitre.org/data/definitions/79.html
SQL Injection - MySQL HIGH RISK
CONFIDENCE
Medium PREDICTED SCORE
N/ATARGET URL
http://testphp.vulnweb.com/artists.ph...
DESCRIPTION
SQL injection may be possible.
REMEDIATION SOLUTION
Do not trust client side input, even if there is client side validation in place.
In general, type check all data on the server side.
If the application uses JDBC, use PreparedStatement or CallableStatement, with parameters 
passed by '?'
If the application uses ASP, use ADO Command Objects with strong type checking and 
parameterized queries.
If database Stored Procedures can be used, use them.
Do *not* concatenate strings into queries in the stored procedure, or use 'exec', 'exec 
immediate', or equivalent functionality!
Do not create dynamic SQL queries using simple string concatenation.
Escape all data received from the client.
Apply an 'allow list' of allowed characters, or a 'deny list' of disallowed characters in 
user input.
Apply the principle of least privilege by using the least privileged database user 
possible.
In particular, avoid using the 'sa' or 'db-owner' database users. This does not eliminate 
SQL injection, but minimizes its impact.
Grant the minimum database access that is necessary for the application.
REFERENCES
https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
Page 5 of 15
Absence of Anti-CSRF Tokens MEDIUM RISK
CONFIDENCE
Low PREDICTED SCORE
12.77TARGET URL
http://testphp.vulnweb.com/artists.ph...
DESCRIPTION
No Anti-CSRF tokens were found in a HTML submission form.
A cross-site request forgery is an attack that involves forcing a victim to send an HTTP 
request to a target destination without their knowledge or intent in order to perform an 
action as the victim. The underlying cause is application functionality using predictable 
URL/form actions in a repeatable way. The nature of the attack is that CSRF exploits the 
trust that a web site has for a user. By contrast, cross-site scripting (XSS) exploits the 
trust that a user has for a web site. Like XSS, CSRF attacks are not necessarily cross-
site, but they can be. Cross-site request forgery is also known as CSRF, XSRF, one-click 
attack, session riding, confused deputy, and sea surf.
CSRF attacks are effective in a number of situations, including:
    * The victim has an active session on the target site.
    * The victim is authenticated via HTTP auth on the target site.
    * The victim is on the same local network as the target site.
CSRF has primarily been used to perform an action against a target site using the victim's 
privileges, but recent techniques have been discovered to disclose information by gaining 
access to the response. The risk of information disclosure is dramatically increased when 
the target site is vulnerable to XSS, because XSS can be used as a platform for CSRF, 
allowing the attack to operate within the bounds of the same-origin policy.
REMEDIATION SOLUTION
Phase: Architecture and Design
Use a vetted library or framework that does not allow this weakness to occur or provides 
constructs that make this weakness easier to avoid.
For example, use anti-CSRF packages such as the OWASP CSRFGuard.
Phase: Implementation
Ensure that your application is free of cross-site scripting issues, because most CSRF 
defenses can be bypassed using attacker-controlled script.
Phase: Architecture and Design
Generate a unique nonce for each form, place the nonce into the form, and verify the nonce 
upon receipt of the form. Be sure that the nonce is not predictable (CWE-330).
Note that this can be bypassed using XSS.
Identify especially dangerous operations. When the user performs a dangerous operation, 
send a separate confirmation request to ensure that the user intended to perform that 
operation.
Note that this can be bypassed using XSS.
Use the ESAPI Session Management control.
Page 6 of 15
This control includes a component for CSRF.
Do not use the GET method for any request that triggers a state change.
Phase: Implementation
Check the HTTP Referer header to see if the request originated from an expected page. This 
could break legitimate functionality, because users or proxies may have disabled sending 
the Referer for privacy reasons.
REFERENCES
https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
https://cwe.mitre.org/data/definitions/352.html
Missing Anti-clickjacking Header MEDIUM RISK
CONFIDENCE
Medium PREDICTED SCORE
11.0TARGET URL
http://testphp.vulnweb.com/AJAX/
index.php
DESCRIPTION
The response does not protect against 'ClickJacking' attacks. It should include either 
Content-Security-Policy with 'frame-ancestors' directive or X-Frame-Options.
REMEDIATION SOLUTION
Modern Web browsers support the Content-Security-Policy and X-Frame-Options HTTP headers. 
Ensure one of them is set on all web pages returned by your site/app.
If you expect the page to be framed only by pages on your server (e.g. it's part of a 
FRAMESET) then you'll want to use SAMEORIGIN, otherwise if you never expect the page to be 
framed, you should use DENY. Alternatively consider implementing Content Security Policy's 
"frame-ancestors" directive.
REFERENCES
https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options
Page 7 of 15
HTTP Only Site MEDIUM RISK
CONFIDENCE
Medium PREDICTED SCORE
9.23TARGET URL
http://testphp.vulnweb.com/artists.ph...
DESCRIPTION
The site is only served under HTTP and not HTTPS.
REMEDIATION SOLUTION
Configure your web or application server to use SSL (https).
REFERENCES
https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html
https://letsencrypt.org/
Page 8 of 15
Content Security Policy (CSP) Header Not Set MEDIUM RISK
CONFIDENCE
High PREDICTED SCORE
5.25TARGET URL
http://testphp.vulnweb.com/artists.ph...
DESCRIPTION
Content Security Policy (CSP) is an added layer of security that helps to detect and 
mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection 
attacks. These attacks are used for everything from data theft to site defacement or 
distribution of malware. CSP provides a set of standard HTTP headers that allow website 
owners to declare approved sources of content that browsers should be allowed to load on 
that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable 
objects such as Java applets, ActiveX, audio and video files.
REMEDIATION SOLUTION
Ensure that your web server, application server, load balancer, etc. is configured to set 
the Content-Security-Policy header.
REFERENCES
https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP
https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
https://www.w3.org/TR/CSP/
https://w3c.github.io/webappsec-csp/
https://web.dev/articles/csp
https://caniuse.com/#feat=contentsecuritypolicy
https://content-security-policy.com/
Page 9 of 15
In Page Banner Information Leak LOW RISK
CONFIDENCE
High PREDICTED SCORE
9.88TARGET URL
http://testphp.vulnweb.com/high
DESCRIPTION
The server returned a version banner string in the response content. Such information leaks 
may allow attackers to further target specific issues impacting the product and version in 
use.
REMEDIATION SOLUTION
Configure the server to prevent such information leaks. For example:
Under Tomcat this is done via the "server" directive and implementation of custom error 
pages.
Under Apache this is done via the "ServerSignature" and "ServerTokens" directives.
REFERENCES
https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/08-
Testing_for_Error_Handling/
Page 10 of 15
Server Leaks Information via "X-Powered-By" HTTP Response
Header Field(s)LOW RISK
CONFIDENCE
Medium PREDICTED SCORE
9.88TARGET URL
http://testphp.vulnweb.com/AJAX/
index.php
DESCRIPTION
The web/application server is leaking information via one or more "X-Powered-By" HTTP 
response headers. Access to such information may facilitate attackers identifying other 
frameworks/components your web application is reliant upon and the vulnerabilities such 
components may be subject to.
REMEDIATION SOLUTION
Ensure that your web server, application server, load balancer, etc. is configured to 
suppress "X-Powered-By" headers.
REFERENCES
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/
08-Fingerprint_Web_Application_Framework
https://www.troyhunt.com/shhh-dont-let-your-response-headers/
Page 11 of 15
Server Leaks Version Information via "Server" HTTP Response
Header FieldLOW RISK
CONFIDENCE
High PREDICTED SCORE
9.88TARGET URL
http://testphp.vulnweb.com/AJAX/
index.php
DESCRIPTION
The web/application server is leaking version information via the "Server" HTTP response 
header. Access to such information may facilitate attackers identifying other 
vulnerabilities your web/application server is subject to.
REMEDIATION SOLUTION
Ensure that your web server, application server, load balancer, etc. is configured to 
suppress the "Server" header or provide generic details.
REFERENCES
https://httpd.apache.org/docs/current/mod/core.html#servertokens
https://learn.microsoft.com/en-us/previous-versions/msp-n-p/ff648552(v=pandp.10)
https://www.troyhunt.com/shhh-dont-let-your-response-headers/
Page 12 of 15
X-Content-Type-Options Header Missing LOW RISK
CONFIDENCE
Medium PREDICTED SCORE
5.25TARGET URL
http://testphp.vulnweb.com/AJAX/
index.php
DESCRIPTION
The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows 
older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response 
body, potentially causing the response body to be interpreted and displayed as a content 
type other than the declared content type. Current (early 2014) and legacy versions of 
Firefox will use the declared content type (if one is set), rather than performing MIME-
sniffing.
REMEDIATION SOLUTION
Ensure that the application/web server sets the Content-Type header appropriately, and that 
it sets the X-Content-Type-Options header to 'nosniff' for all web pages.
If possible, ensure that the end user uses a standards-compliant and modern web browser 
that does not perform MIME-sniffing at all, or that can be directed by the web application/
web server to not perform MIME-sniffing.
REFERENCES
https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/gg622941(v=vs.85)
https://owasp.org/www-community/Security_Headers
Page 13 of 15
User Controllable HTML Element Attribute (Potential XSS) INFO RISK
CONFIDENCE
Low PREDICTED SCORE
9.39TARGET URL
http://testphp.vulnweb.com/
guestbook.php
DESCRIPTION
This check looks at user-supplied input in query string parameters and POST data to 
identify where certain HTML attribute values might be controlled. This provides hot-spot 
detection for XSS (cross-site scripting) that will require further review by a security 
analyst to determine exploitability.
REMEDIATION SOLUTION
Validate all input and sanitize output it before writing to any HTML attributes.
REFERENCES
https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
Authentication Request Identified INFO RISK
CONFIDENCE
Low PREDICTED SCORE
N/ATARGET URL
http://testphp.vulnweb.com/secured/
ne...
DESCRIPTION
The given request has been identified as an authentication request. The 'Other Info' field 
contains a set of key=value lines which identify any relevant fields. If the request is in 
a context which has an Authentication Method set to "Auto-Detect" then this rule will 
change the authentication to match the request identified.
REMEDIATION SOLUTION
This is an informational alert rather than a vulnerability and so there is nothing to fix.
REFERENCES
https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/
Page 14 of 15
NETSHIELDAI REPORTING ENGINE // ZAP SCANNER // GENERATED 2026-01-07 16:28:49 Charset Mismatch (Header Versus Meta Content-Type Charset) INFO RISK
CONFIDENCE
Low PREDICTED SCORE
N/ATARGET URL
http://testphp.vulnweb.com/AJAX/
index.php
DESCRIPTION
This check identifies responses where the HTTP Content-Type header declares a charset 
different from the charset defined by the body of the HTML or XML. When there's a charset 
mismatch between the HTTP header and content body Web browsers can be forced into an 
undesirable content-sniffing mode to determine the content's correct character set.
An attacker could manipulate content on the page to be interpreted in an encoding of their 
choice. For example, if an attacker can control content at the beginning of the page, they 
could inject script using UTF-7 encoded text and manipulate some browsers into interpreting 
that text.
REMEDIATION SOLUTION
Force UTF-8 for all text content in both the HTTP header and meta tags in HTML or encoding 
declarations in XML.
REFERENCES
https://code.google.com/archive/p/browsersec/wikis/Part2.wiki#Character_set_handling_and_detection
Modern Web Application INFO RISK
CONFIDENCE
Medium PREDICTED SCORE
N/ATARGET URL
http://testphp.vulnweb.com/AJAX/
index.php
DESCRIPTION
The application appears to be a modern web application. If you need to explore it 
automatically then the Ajax Spider may well be more effective than the standard one.
REMEDIATION SOLUTION
This is an informational alert and so no changes are required.
Page 15 of 15

"""
    result = parse_zap_report(test_text)
    print(json.dumps(result, indent=2))