import 'dart:io';
import 'dart:convert';
import 'package:http/http.dart' as http;

void main() async {
  print("Enter target URL (e.g., http://example.com): ");
  String? target = stdin.readLineSync()?.trim();
  if (target == null || target.isEmpty) {
    print("Invalid target!");
    return;
  }

  await checkHeaders(target);
  await dirEnumeration(target);
  await subdomainDiscovery(target);
  await sqlInjectionCheck(target);
  await xssCheck(target);
  await portScan(target);
  await checkSecurityHeaders(target);
}

Future<void> checkHeaders(String url) async {
  print("\n[+] Checking HTTP Headers...");
  try {
    var response = await http.get(Uri.parse(url));
    response.headers.forEach((key, value) {
      print("$key: $value");
    });
  } catch (e) {
    print("Error fetching headers: $e");
  }
}

Future<void> dirEnumeration(String url) async {
  print("\n[+] Performing Directory Enumeration...");
  String wordlistUrl = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt";
  try {
    var wordlistResponse = await http.get(Uri.parse(wordlistUrl));
    if (wordlistResponse.statusCode == 200) {
      List<String> dirs = wordlistResponse.body.split("\n");
      for (var dir in dirs) {
        var fullUrl = "$url/$dir";
        try {
          var response = await http.get(Uri.parse(fullUrl));
          if (response.statusCode == 200) {
            print("[FOUND] $fullUrl");
          }
        } catch (e) {
          print("Error scanning $fullUrl: $e");
        }
      }
    } else {
      print("Failed to fetch wordlist from SecLists");
    }
  } catch (e) {
    print("Error fetching wordlist: $e");
  }
}

Future<void> subdomainDiscovery(String url) async {
  print("\n[+] Performing Subdomain Discovery...");
  Uri parsedUrl = Uri.parse(url);
  String domain = parsedUrl.host;
  String apiUrl = "https://crt.sh/?q=$domain&output=json";

  try {
    var response = await http.get(Uri.parse(apiUrl));
    if (response.statusCode == 200) {
      List<dynamic> jsonData = jsonDecode(response.body);
      Set<String> subdomains = {};

      for (var entry in jsonData) {
        if (entry["name_value"] != null) {
          subdomains.addAll(entry["name_value"].split("\n"));
        }
      }

      print("[+] Found Subdomains:");
      for (var sub in subdomains) {
        print(sub);
      }
    } else {
      print("Failed to fetch subdomains from crt.sh");
    }
  } catch (e) {
    print("Error fetching subdomains: $e");
  }
}

Future<void> sqlInjectionCheck(String url) async {
  print("\n[+] Checking for Basic SQL Injection...");
  List<String> payloads = ["' OR '1'='1", "' OR '1'='1' -- ", "admin' -- ", "' UNION SELECT 1,2,3 -- "];
  
  for (var payload in payloads) {
    var testUrl = "$url?id=$payload";
    try {
      var response = await http.get(Uri.parse(testUrl));
      if (response.body.contains("SQL syntax") || response.body.contains("mysql")) {
        print("[VULNERABLE] $testUrl");
      }
    } catch (e) {
      print("Error testing $testUrl: $e");
    }
  }
}

Future<void> xssCheck(String url) async {
  print("\n[+] Checking for XSS Vulnerabilities...");
  List<String> payloads = ["<script>alert('XSS')</script>", "\" onmouseover=alert('XSS') "]; 
  
  for (var payload in payloads) {
    var testUrl = "$url?q=$payload";
    try {
      var response = await http.get(Uri.parse(testUrl));
      if (response.body.contains(payload)) {
        print("[VULNERABLE] XSS detected at $testUrl");
      }
    } catch (e) {
      print("Error testing $testUrl: $e");
    }
  }
}

Future<void> portScan(String url) async {
  print("\n[+] Performing Port Scan...");
  List<int> ports = [21, 22, 80, 443, 3306, 8080];
  String host = Uri.parse(url).host;
  
  for (var port in ports) {
    try {
      var socket = await Socket.connect(host, port, timeout: Duration(seconds: 2));
      print("[OPEN] $host:$port");
      socket.destroy();
    } catch (e) {
      print("[CLOSED] $host:$port");
    }
  }
}

Future<void> checkSecurityHeaders(String url) async {
  print("\n[+] Checking for Security Headers...");
  try {
    var response = await http.get(Uri.parse(url));
    List<String> securityHeaders = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-XSS-Protection"];
    for (var header in securityHeaders) {
      if (!response.headers.containsKey(header.toLowerCase())) {
        print("[MISSING] $header");
      }
    }
  } catch (e) {
    print("Error fetching security headers: $e");
  }
}
