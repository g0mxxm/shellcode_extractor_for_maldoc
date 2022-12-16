#!/usr/bin/python3
import sys
import os
import re
import subprocess
import getopt

oleid = "/usr/local/bin/oleid"
msoffcrypto_crack = "/usr/local/bin/msoffcrypto-crack.py"
oledump = "/usr/bin/oledump.py"
xorsearch = "/usr/bin/xorsearch"
scdbgc = "/usr/bin/scdbgc"
grep = "/usr/bin/grep"
cut_bytes = "/usr/local/bin/cut-bytes.py"
rtfdump = "/usr/local/bin/rtfdump.py"
zipdump = "/usr/local/bin/zipdump.py"
#init_file = '/home/remnux/files/Down/0739f7d08c0364d12c6b40362ccd610d.dat'
init_file = ''
decrypted_file = "/home/remnux/files/shellcode/shellcode_decrypted"
shellcode_file = "/home/remnux/files/shellcode/shellcode_file"
shellcode_file_unpack = "/home/remnux/files/shellcode/shellcode_file.unpack"
final_shellcode_file = "/home/remnux/files/shellcode/final_shellcode_file"

def check_OOXML_contain(file):
    try:
        dump = subprocess.Popen([zipdump, file], stdout = subprocess.PIPE)
        dump = subprocess.check_output([grep, '.bin'], stdin = dump.stdout, encoding = 'utf-8')
        #print("dump:" + dump)
        return True
    except Exception as e:
        print('[-] check_OOXML_contain failure...')
        print(e)
        #sys.exit(1)

def check_container_format(file):
    try:
        dump = subprocess.Popen([oleid, file], stdout = subprocess.PIPE)
        dump = subprocess.check_output([grep, 'Container format'], stdin = dump.stdout, encoding = 'utf-8')
        #print(dump)
        if dump.find("RTF") >= 0:
            print("The Container format of this file is RTF")
            return 1
        elif dump.find("OLE") >= 0:
            print("The Container format of this file is OLE")
            return 2
        elif dump.find("OpenXML") >= 0:
            print("The Container format of this file is OpenXML")
            return 3
    except Exception as e:
        print('[-] check_container_format failure...')
        print(e)
        sys.exit(1)

def find_ole_from_rtf(file_name):
    ole_sign = []
    try:
        ole_signdump = subprocess.Popen([rtfdump, '-F', file_name], stdout = subprocess.PIPE)
        ole_dump_decode = ole_signdump.stdout.read().decode('utf-8')
        #print("ole_dump_decode:" + ole_dump_decode)
        for i in ole_dump_decode.split('\n'):
            if i.endswith(':'):
                ole_sign.append(i[0:i.find(':')])
        #print("ole_sign:" + str(ole_sign))
        return ole_sign
    except Exception as e:
        print('[-] find_ole_from_rtf failure...')
        print(e)
        sys.exit(1)

def extract_ole_from_rtf(file_name):
    ole_sign = find_ole_from_rtf(file_name)
    sign_count = -1
    ole_object = []
    try:
        for temp_ole_sign in ole_sign:
            sign_count = sign_count + 1
            ole_object.append("/home/remnux/files/shellcode/ole_object_" + str(sign_count))
            with open(ole_object[sign_count], 'w') as outfile:
                subprocess.run([rtfdump, '-F', '-s', temp_ole_sign, '-d', file_name], stdout = outfile)
        return ole_object
    except Exception as e:
        print('[-] extract_ole_from_rtf failure...')
        print(e)
        return False

def obtain_stream_sign(file_name):
    stream_sign = []
    try:
        stream_dump = subprocess.Popen([oledump, file_name], stdout = subprocess.PIPE)
        stream_dump_decoded = stream_dump.stdout.read().decode('utf-8')
        for i in stream_dump_decoded.split('\n'):
            if i.startswith(' '):
                stream_sign.append(i[1:i.find(":")])
            #else:
                #stream_sign.append(i[0:i.find(":")])
        #stream_sign = stream_sign[0:-1]
        count = 0
        for i in stream_sign:
            stream_sign[count] = i.lstrip(' ')
            count = count + 1
        #print(stream_sign)
        return stream_sign
    except Exception as e:
        print('[-] check_and_dump_streams failure...')
        print(e)
        sys.exit(1)

def obtain_and_check_stream_block(file_name):
    stream_sign = []
    stream_sign = obtain_stream_sign(file_name)
    best_score = -1
    final_sign = ''
    #print(stream_sign)
    try:
        for sign_temp in stream_sign:
            #print(sign_temp)
            stream_block = subprocess.Popen([oledump, '-s', sign_temp, '-d', file_name], stdout = subprocess.PIPE)
            #stream_block_decode = stream_block.stdout.read().decode('utf-8')
            #print(stream_block_decode)
            check_info = subprocess.run([xorsearch, '-W', '-'], stdin = stream_block.stdout, stdout = subprocess.PIPE)
            check_info_decode = check_info.stdout.decode('utf-8')
            #print(check_info_decode)
            for i in check_info_decode.split('\n'):
                if i.startswith('Score:'):
                    temp_socre_str = re.findall(r"\d+",i)
                    temp_score = int(temp_socre_str[0])
                    if temp_score > best_score:
                        best_score = temp_score
                        final_sign = sign_temp
                    #print(best_score)
                    #print(final_sign)
        #print(best_score)
        if best_score <= 0:
            return -1
        else:
            return final_sign
    except Exception as e:
        print('[-] obtain_stream_block failure...')
        print(e)
        sys.exit(1)

def decrypted(file):
    try:
        statecode = subprocess.check_call([msoffcrypto_crack, '-o', decrypted_file, file])
        #print("statecode:", statecode)
    except subprocess.CalledProcessError as e:
        print('[-] decrypted failure...')
        print(e.output)
        sys.exit(1)

def check_encrypted(file):
    try:
        dump = subprocess.Popen([oleid, file], stdout = subprocess.PIPE)
        dump = subprocess.check_output([grep, 'Encrypted'], stdin = dump.stdout, encoding = 'utf-8')
        if dump.find("True") >= 0:
            print("The document is encrypted!")
            return True
        else:
            print("The document is not encrypted!")
            return False
    except Exception as e:
        print('[-] check_encrypted failure...')
        print(e)
        sys.exit(1)

def locate_and_extract_shellcode(block_sign, file_name):
    position = []
    start_pos = ''
    try:
        stream_block = subprocess.Popen([oledump, '-s', block_sign, '-d', file_name], stdout = subprocess.PIPE)
        check_info = subprocess.run([xorsearch, '-W', '-'], stdin = stream_block.stdout, stdout = subprocess.PIPE)
        check_info_decode = (check_info.stdout.decode('utf-8'))
        with open(shellcode_file, 'w') as outfile:
            subprocess.run([oledump, '-s', block_sign, '-d', file_name], stdout = outfile)
        #print(check_info_decode)
        for i in check_info_decode.split('\n'):
                if i.startswith('Found'):
                    single_pos = i[(i.find('position') + 9):i.find(':')]
                    if single_pos in position:
                        continue
                    else:
                        position.append(single_pos) 
        #print(position)
        #return position, stream_block
        for pos in position:
            shellcode_dump = subprocess.run([scdbgc, '-f', shellcode_file, '-foff', pos, '-d'], stdout = subprocess.PIPE)
            #print(shellcode_dump)
            shellcode_dump_decode = shellcode_dump.stdout.decode('utf-8')
            #print(shellcode_dump_decode)
            for i in shellcode_dump_decode.split('\n'):
                if i.startswith('Change found'):
                    start_pos = re.findall(r"\d+",i)
                else:
                    continue
            #print(start_pos)
        if isinstance(start_pos,str):
            print("The shellcode you needed is in the shellcode_file")
        else:
            final_start_pos = str(start_pos[-1]) + ':'
            #print(final_start_pos)
            with open(final_shellcode_file, 'w') as outfile:
                subprocess.run([cut_bytes, '-d', final_start_pos, shellcode_file_unpack], stdout = outfile)
            print("The shellcode you needed is in the final_shellcode_file")
    except Exception as e:
        print('[-] extractor_shellcode failure...')
        print(e)
        sys.exit(1)

if __name__ == '__main__':
    init_file = input("Please input the Maldoc include which shellcode you need:")
    encrypt_flag = check_encrypted(init_file)
    type_code = check_container_format(init_file)
    if type_code == 1:
        if encrypt_flag == True:
            decrypted(init_file)
            ole_object_file = extract_ole_from_rtf(decrypted_file)
            for temp_ole_object_file in ole_object_file:
                block_sign = obtain_and_check_stream_block(temp_ole_object_file)
                if block_sign != -1:
                    locate_and_extract_shellcode(block_sign,temp_ole_object_file)
                else:
                    print('[-] extractor_shellcode failure...')
                    print("Because this file doesn't contain ole object or it doesn't contain shellcode")
        else:
            ole_object_file = extract_ole_from_rtf(init_file)
            for temp_ole_object_file in ole_object_file:
                block_sign = obtain_and_check_stream_block(temp_ole_object_file)
                if block_sign != -1:
                    locate_and_extract_shellcode(block_sign,temp_ole_object_file)
                else:
                    print('[-] extractor_shellcode failure...')
                    print("Because this file doesn't contain ole object or it doesn't contain shellcode")

    elif type_code == 2:
        if encrypt_flag == True:
            decrypted(init_file)
            block_sign = obtain_and_check_stream_block(decrypted_file)
            if block_sign != -1:
                locate_and_extract_shellcode(block_sign,decrypted_file)
            else:
                print('[-] extractor_shellcode failure...')
                print("Because this file doesn't contain ole object or it doesn't contain shellcode") 
        else:
            block_sign = obtain_and_check_stream_block(init_file)
            if block_sign != -1:
                locate_and_extract_shellcode(block_sign,init_file)
            else:
                print('[-] extractor_shellcode failure...')
                print("Because this file doesn't contain ole object or it doesn't contain shellcode") 
    
    elif type_code == 3:
        if encrypt_flag == True:
            decrypted(init_file)
            bin_flag = check_OOXML_contain(decrypted_file)
            if bin_flag == True:
                block_sign = obtain_and_check_stream_block(init_file)
                if block_sign != -1:
                    locate_and_extract_shellcode(block_sign,init_file)
                else:
                    print('[-] extractor_shellcode failure...')
                    print("Because this file doesn't contain ole object or it doesn't contain shellcode") 
            else:
                print('[-] extractor_shellcode failure...')
                print("Because this file doesn't contain ole object or it doesn't contain shellcode")
                print("This file will download the shellcode you need from C2, Please check the behavior of the Network communications")
        else:
            bin_flag = check_OOXML_contain(init_file)
            if bin_flag == True:
                block_sign = obtain_and_check_stream_block(init_file)
                if block_sign != -1:
                    locate_and_extract_shellcode(block_sign,init_file)
                else:
                    print('[-] extractor_shellcode failure...')
                    print("Because this file doesn't contain ole object or it doesn't contain shellcode") 
            else:
                print('[-] extractor_shellcode failure...')
                print("Because this file doesn't contain ole object or it doesn't contain shellcode")
                print("This file will download the shellcode you need from C2, Please check the behavior of the Network communications")

        
