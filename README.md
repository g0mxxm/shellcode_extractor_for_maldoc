The code in this repository which function is to extract the shellcode from the maldoc  
# Introduction  
In my daily analysis, I will face many maldoc. Most maldoc contain shellcode, so we have to face the problem of how to quickly extract shellcode from it and analyze its behavior. This tool solves this problem very well by combining existing analysis tools to form a tool chain. And if you want know more details of this tool, you can read this [article]() I wrote
# Install  
## Environment  
* python3 & javascript  
* REMnux or any enviroment that include these tools (zipdump & rtfdump & xorsearch & scdbg & cut-bytes)   
* Windows + Office + frida (If you want to use the hook function to extract the OLE object from the RTF file)  
## Code  
You only need to clone this repository  
# Usage 
## Extract OLE from RTF by hook  
### Environment
Windows + Office + frida  
### Code
in the hook folder (you need modify the storage location of the OLE object which is dumped from RTF)
### Bash 
```bash
python3 "$(The path of hook.py)" -n "$(The path of WINWORD.exe) $(The path of RTF file)" "$(The path of hook_OLE.mjs)"
```
## Shellcode extractor  
### Environment
REMnux or any enviroment that include these tools (zipdump & rtfdump & xorsearch & scdbg & cut-bytes)
### Code  
shellcode_extractor.py (you need to make sure that the tool path in the python file matches the environment you are using. At the same time you can modify the storage location of the shellcode file which is dumped from maldoc) 
### Bash  
```bash
python3 "$(The path of shellcode_extractor.py)"
```  
# Examples  
## Extract OLE from RTF by hook
![2022-12-15-22-23-40](https://raw.githubusercontent.com/g0mxxm/Picture/main/images/2022-12-15-22-23-40.png)  
## Shellcode extractor  
![2022-12-15-22-32-06](https://raw.githubusercontent.com/g0mxxm/Picture/main/images/2022-12-15-22-32-06.png)  

# Reference 
* Environment is [Remnux](https://remnux.org/) docker 
* [Didier Stevens](https://isc.sans.edu/handler_list.html#didier-stevens) 's tools and blogs   
* [oletools](https://github.com/decalage2/oletools)  
* [frida-python github](https://github.com/frida/frida-python)
* [frida's official document](https://frida.re/docs/home/)  
* Denis O'Brien's [Silver Bullet](http://malwageddon.blogspot.com/2018/11/deobfuscation-tips-rtf-files.html)
* DarunGrim's [Using Frida For Windows Reverse Engineering](https://darungrim.com/research/2020-06-17-using-frida-for-windows-reverse-engineering.html)