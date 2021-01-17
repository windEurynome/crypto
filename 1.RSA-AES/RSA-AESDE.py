# -*- coding: utf-8 -*-
# author： Eurynome (2020-11-08)
# reference: Soreat_u (2019-06-09)
# reference: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf



from Arithmetic import gmul
import binascii
import base64
from base64 import binascii
import rsa


# base64->hexstr
def base64_decode(base64_data):
  	temp = base64.b64decode(base64_data).hex()
  	return temp



'''
AES (Advance Encryption Standard) implementation.
'''


S_box = (0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,)
InvS_box = (0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,)
Rcon = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,)


# encrytion & decryption layers
def SubBytes(s):
    '''
    A non-linear substitution step where each byte is replaced with another according to a lookup table
    :param list s: 16-byte list of the state
    :no return
    '''
    for i in range(16):
        s[i] = S_box[s[i]]

def InvSubBytes(s):
    '''
    Inverse of SubBytes
    :param list s: 16-byte list of the state
    :no return
    '''
    for i in range(16):
        s[i]= InvS_box[s[i]]

def ShiftRows(s):
    '''
    A transposition step where the last three rows of the state are shifted cyclically a certain number of steps
    :param list s: 16-byte list of the state
    :no return
    '''
    s[:] = list(s[0::5] + s[4::5] + s[3:4:5] + s[8::5] + s[2:8:5] + s[12::5] + s[1:12:5])

def InvShiftRows(s):
    '''
    Inverse of ShiftRows 
    :param list s: 16-byte list of the state
    :no return
    '''
    s[:] = [s[0],s[13],s[10],s[7],s[4],s[1],s[14],s[11],s[8],s[5],s[2],s[15],s[12],s[9],s[6],s[3]]

def MixColumns(s):
    '''
    A linear mixing operation which operates on the columns of the state, combining the four bytes in each column
    :param list s: 16-byte list of the state
    :no return
    '''
    # learnt from https://github.com/bozhu/AES-Python/blob/master/aes.py
    xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)
    for i in range(4):
        t = s[4*i] ^ s[4*i+1] ^ s[4*i+2] ^ s[4*i+3]
        u = s[4*i]
        s[4*i]   ^= t ^ xtime(s[4*i]   ^ s[4*i+1])
        s[4*i+1] ^= t ^ xtime(s[4*i+1] ^ s[4*i+2])
        s[4*i+2] ^= t ^ xtime(s[4*i+2] ^ s[4*i+3])
        s[4*i+3] ^= t ^ xtime(s[4*i+3] ^ u)
        #  fips-197 5.1.3
        # s[4*i], s[4*i+1], s[4*i+2], s[4*i+3] = \
        #     gmul(0x02, s[4*i]) ^ gmul(0x03, s[4*i+1]) ^ s[4*i+2]             ^ s[4*i+3],\
        #     s[4*i]             ^ gmul(0x02, s[4*i+1]) ^ gmul(0x03, s[4*i+2]) ^ s[4*i+3],\
        #     s[4*i]             ^ s[4*i+1]             ^ gmul(0x02, s[4*i+2]) ^ gmul(0x03, s[4*i+3]),\
        #     gmul(0x03, s[4*i]) ^ s[4*i+1]             ^ s[4*i+2]             ^ gmul(0x02,s[4*i+3])

def InvMixColumns(s):
    '''
    Inverse of MixColumns
    :param list s: 16-byte list of the state
    :no return
    '''
    # fips-197 5.3.3
    for i in range(4):
        s[4*i], s[4*i+1], s[4*i+2], s[4*i+3] = \
            gmul(0x0e, s[4*i]) ^ gmul(0x0b, s[4*i+1]) ^ gmul(0x0d, s[4*i+2]) ^ gmul(0x09, s[4*i+3]),\
            gmul(0x09, s[4*i]) ^ gmul(0x0e, s[4*i+1]) ^ gmul(0x0b, s[4*i+2]) ^ gmul(0x0d, s[4*i+3]),\
            gmul(0x0d, s[4*i]) ^ gmul(0x09, s[4*i+1]) ^ gmul(0x0e, s[4*i+2]) ^ gmul(0x0b, s[4*i+3]),\
            gmul(0x0b, s[4*i]) ^ gmul(0x0d, s[4*i+1]) ^ gmul(0x09, s[4*i+2]) ^ gmul(0x0e, s[4*i+3])

def AddRoundKey(s, k):
    '''
    Combine each byte of the state with a block(16-byte) round key using bitwise xor
    :param list s: 16-byte list of the state
    :param list k: 16-byte list of the subkey
    :no return
    '''
    for i in range(16):
        s[i]^=k[i]


# key schedule
def SubWord(w):
    '''
    :param list w: 4-byte list
    :return: 4-byte list after substitution
    :rtype: list
    '''
    return [S_box[w[i]] for i in range(4)]

def RotWord(w):
    '''
    :param list w: 4-byte list
    :return: 4-byte list after rotation
    :rtype: list
    '''
    return w[1:]+w[0:1]

def WordXor(w1, w2):
    '''
    Perform XOR operation on two words(4 bytes)
    
    :param list w1: the first word(4 bytes)
    :param list w2: the second word(4 bytes)
    :return: 4-byte lis after the XOR operation
    :rtype: list
    '''
    return [w1[i]^w2[i] for i in range(4)]

def KeyExpansion(k, r):
    '''
    Perform a Key Expansion routine to generate a key schedule
    :param list(or bytes) k: the Cipher Key
    :param int r: number of rounds
    :return: generated subkeys
    :rtype: list of 4-byte lists
    '''
    # fips-197 Figure 11
    k=list(k) # in case k is bytes
    Nk = len(k) // 4
    subkeys = [k[i:i+4] for i in range(0, 4*Nk, 4)]
    
    i = Nk
    while i < 4 * (r + 1):
        t = subkeys[i - 1]
        if i % Nk == 0:
            tt = SubWord(RotWord(t))
            t = [tt[0] ^Rcon[i//Nk]] + tt[1:]
        elif Nk > 6 and i % Nk == 4:
            t = SubWord(t)
        subkeys.append(WordXor(subkeys[i - Nk], t))
        i+=1
    return subkeys

# encryption & decryption function
def AES_enc(input, key):
    '''
    Encryption of AES
    :param bytes input: 128-bit bytes of plaintext
    :param bytes key: 128-bit(or 196-bit or 256-bit) bytes of key
    :return: 128-bit bytes ciphertext after encrytion
    :rtype: bytes
    :raise ValueError: if the length of key is invalid
    '''
    # check key length
    if len(key) not in (16, 24, 32):
        raise ValueError("Invalid key size")
    
    # Calculate number of rounds according to the length of key
    number_of_rounds = {16: 10, 24: 12, 32: 14}
    rounds = number_of_rounds[len(key)]

    ''' All the `##` are for test2() '''
    r = 0
    ## print("round[%2d].input    %s" % (r, binascii.hexlify(input)))
    
    # Generate subkeys
    subks = KeyExpansion(key, rounds)
    
    # start
    k_sch = subks[0] + subks[1] + subks[2] + subks[3]
    ## print("round[%2d].k_sch    %s" % (r, binascii.hexlify(bytes(k_sch))))

    state = list(input)
    AddRoundKey(state, k_sch)    

    # round 1 ~ `rounds`-1
    for r in range(1, rounds):
        ## print("round[%2d].start    %s" % (r, binascii.hexlify(bytes(state))))
        SubBytes(state)
        ## print("round[%2d].s_box    %s" % (r, binascii.hexlify(bytes(state))))
        ShiftRows(state)
        ## print("round[%2d].s_row    %s" % (r, binascii.hexlify(bytes(state))))
        MixColumns(state)
        ## print("round[%2d].m_col    %s" % (r, binascii.hexlify(bytes(state))))
        k_sch = subks[4*r] + subks[4*r+1] + subks[4*r+2] + subks[4*r+3]
        ## print("round[%2d].k_sch    %s" % (r, binascii.hexlify(bytes(k_sch))))
        AddRoundKey(state, k_sch)
    
    # the last round
    r = rounds
    ## print("round[%2d].start    %s" % (r, binascii.hexlify(bytes(state))))
    SubBytes(state)
    ## print("round[%2d].s_box    %s" % (r, binascii.hexlify(bytes(state))))
    ShiftRows(state)
    ## print("round[%2d].s_row    %s" % (r, binascii.hexlify(bytes(state))))
    k_sch = subks[-4] + subks[-3] + subks[-2] + subks[-1]
    ## print("round[%2d].k_sch    %s" % (r, binascii.hexlify(bytes(k_sch))))
    AddRoundKey(state, k_sch)
    
    # convert `list` state to `bytes` output
    output = bytes(state)
    ## print("round[%2d].output   %s" % (r, binascii.hexlify(output)))
    return output

def AES_dec(input, key):
    '''
    Decryption of AES
    :param bytes input: 128-bit bytes of ciphertext
    :param bytes key: 128-bit(or 196-bit or 256-bit) bytes of key
    :return: 128-bit bytes plaintext after decrytion
    :rtype: bytes
    :raise ValueError: if the length of key is invalid
    '''
    # check key length
    if len(key) not in (16, 24, 32):
        raise ValueError("Invalid key size")

    # Calculate number of rounds according to the length of key
    number_of_rounds = {16: 10, 24: 12, 32: 14}
    rounds = number_of_rounds[len(key)]

    r = 0
    ## print("round[%2d].iinput   %s" % (r, binascii.hexlify(input)))

    # Generate subkeys for decryption
    subks = KeyExpansion(key, rounds)

    # start
    k_sch = subks[-4] + subks[-3] + subks[-2] + subks[-1]
    ## print("round[%2d].ik_sch   %s" % (r, binascii.hexlify(bytes(k_sch))))

    state = list(input)
    AddRoundKey(state, k_sch)
    
    # round 1 ~ `rounds`-1
    for r in range(1, rounds):
        ## print("round[%2d].istart   %s" % (r, binascii.hexlify(bytes(state))))
        InvShiftRows(state)
        ## print("round[%2d].is_row   %s" % (r, binascii.hexlify(bytes(state))))
        InvSubBytes(state)
        ## print("round[%2d].is_box   %s" % (r, binascii.hexlify(bytes(state))))
        k_sch = subks[-4*r-4]+subks[-4*r-3]+subks[-4*r-2]+subks[-4*r-1]
        ## print("round[%2d].ik_sch   %s" % (r, binascii.hexlify(bytes(k_sch))))
        AddRoundKey(state, k_sch)
        ## print("round[%2d].ik_add   %s" % (r, binascii.hexlify(bytes(state))))
        InvMixColumns(state)

    # the last round
    r = rounds
    ## print("round[%2d].start    %s" % (r, binascii.hexlify(bytes(state))))
    InvShiftRows(state)
    ## print("round[%2d].is_row   %s" % (r, binascii.hexlify(bytes(state))))
    InvSubBytes(state)
    ## print("round[%2d].is_box   %s" % (r, binascii.hexlify(bytes(state))))
    k_sch = subks[0] + subks[1] + subks[2] + subks[3]
    ## print("round[%2d].ik_sch   %s" % (r, binascii.hexlify(bytes(k_sch))))
    AddRoundKey(state, k_sch)
    
    # convert `list` state to `bytes` output
    output = bytes(state)
    ## print("round[%2d].ioutput  %s" % (r, binascii.hexlify(output)))
    return output

'''
# for test
def test1():
    plaintext = bytes([0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34])
    key = bytes([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c])
   ciphertext = AES_enc(plaintext, key)
    recover = AES_dec(ciphertext, key)
    print("plaintext: %s" % plaintext)
    print("ciphertext: %s" % ciphertext)
    print("recover: %s" % recover)
'''

'''
function: make the string to hex
'''

def str_to_hexStr(string):
  str_bin=string.encode('utf-8')
  return binascii.hexlify(str_bin).decode('utf-8')

'''
function: make the hex to bytes
'''

def hexStr_to_str(hexStr):
  hex=hexStr.encode('utf-8')
  bin_str=binascii.unhexlify(hex)
  return bin_str.decode('utf-8')

'''
bytes to string
eg:
b'0123456789ABCDEF0123456789ABCDEF'
'0123456789ABCDEF0123456789ABCDEF'
'''
def bytesToString(bs):
    return bytes.decode(bs,encoding='utf8')


# 汉字；
#chinese = "君不见，黄河之水天上来，奔流到海不复回。君不见，高堂明镜悲白发，朝如青丝暮成雪！人生得意须尽欢，莫使金樽空对月。天生我材必有用，千金散尽还复来。烹羊宰牛且为乐，会须一饮三百杯。岑夫子，丹丘生，将进酒，杯莫停。与君歌一曲，请君为我倾耳听。钟鼓馔玉不足贵，但愿长醉不复醒。古来圣贤皆寂寞，惟有饮者留其名。陈王昔时宴平乐，斗酒十千恣欢谑。主人何为言少钱，径须沽取对君酌。五花马、千金裘，呼儿将出换美酒，与尔同销万古愁！"
with open('E:/0000桌面需要小文件/grade3/密码学课程设计/plaintext.txt','r',encoding='utf-8') as f:
    chinese = f.read()
#print (chinese)

# 字符串转为十六进制；
s_b=str_to_hexStr(chinese)
#print(s_b)

#图片
#with open('E:/0000桌面需要小文件/grade3/密码学课程设计/PIC.jpg','rb') as f:
#    msg = base64.b64encode(f.read())
   
#    f=open('E:/0000桌面需要小文件/grade3/密码学课程设计/PIC.txt','a')
#    s_b= base64_decode(msg)
#    print(s_b,file =f)
#    f.close()
    
    #print(type(s))
    #print(s)
    #print("图片已经base64->16进制字符串，数据存放在PIC.txt中。")
    #print(hex_s)
    #print(type(hex_s)) #bytes
    #print('\n')
    #print('\n')
    #s_b=str_data
    #print(s_b)
    #print(type(s_b))  #str
    #s_b=str_to_hexStr(s_b)
    #print(s_b)


def test():
    #plaintext = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
    #plaintext = bytes().fromhex('87e58fa4e68481efbc81000000000000')
    #key128 = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])
    key196 = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17])
    key256 = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f])
    key128 = bytes().fromhex('000102030405060708090a0b0c0d0e0f')
    #str1=['e5909be4b88de8a781efbc8ce9bb84e6', 'b2b3e4b98be6b0b4e5a4a9e4b88ae69d', 'a5efbc8ce5a594e6b581e588b0e6b5b7', 'e4b88de5a48de59b9ee38082e5909be4', 'b88de8a781efbc8ce9ab98e5a082e698', '8ee9959ce682b2e799bde58f91efbc8c', 'e69c9de5a682e99d92e4b89de69aaee6', '8890e99baaefbc81e4babae7949fe5be', '97e6848fe9a1bbe5b0bde6aca2efbc8c', 'e88eabe4bdbfe98791e6a8bde7a9bae5', 'afb9e69c88e38082e5a4a9e7949fe688', '91e69d90e5bf85e69c89e794a8efbc8c', 'e58d83e98791e695a3e5b0bde8bf98e5', 'a48de69da5e38082e783b9e7be8ae5ae', 'b0e7899be4b894e4b8bae4b990efbc8c', 'e4bc9ae9a1bbe4b880e9a5aee4b889e7', '99bee69dafe38082e5b291e5a4abe5ad', '90efbc8ce4b8b9e4b898e7949fefbc8c', 'e5b086e8bf9be98592efbc8ce69dafe8', '8eabe5819ce38082e4b88ee5909be6ad', '8ce4b880e69bb2efbc8ce8afb7e5909b', 'e4b8bae68891e580bee880b3e590ace3', '8082e9929fe9bc93e9a694e78e89e4b8', '8de8b6b3e8b4b5efbc8ce4bd86e684bf', 'e995bfe98689e4b88de5a48de98692e3', '8082e58fa4e69da5e59ca3e8b4a4e79a', '86e5af82e5af9eefbc8ce6839fe69c89', 'e9a5aee88085e79599e585b6e5908de3', '8082e99988e78e8be69894e697b6e5ae', 'b4e5b9b3e4b990efbc8ce69697e98592', 'e58d81e58d83e681a3e6aca2e8b091e3', '8082e4b8bbe4babae4bd95e4b8bae8a8', '80e5b091e992b1efbc8ce5be84e9a1bb', 'e6b2bde58f96e5afb9e5909be9858ce3', '8082e4ba94e88ab1e9a9ace38081e58d', '83e98791e8a398efbc8ce591bce584bf', 'e5b086e587bae68da2e7be8ee98592ef', 'bc8ce4b88ee5b094e5908ce99480e4b8', '87e58fa4e68481efbc81000000000000']
    #str2=['e5909be4b88de8a781efbc8ce9bb84e6', 'b2b3e4b98be6b0b4e5a4a9e4b88ae69d', 'a5efbc8ce5a594e6b581e588b0e6b5b7', 'e4b88de5a48de59b9ee38082e5909be4', 'b88de8a781efbc8ce9ab98e5a082e698', '8ee9959ce682b2e799bde58f91efbc8c', 'e69c9de5a682e99d92e4b89de69aaee6', '8890e99baaefbc81e4babae7949fe5be', '97e6848fe9a1bbe5b0bde6aca2efbc8c', 'e88eabe4bdbfe98791e6a8bde7a9bae5', 'afb9e69c88e38082e5a4a9e7949fe688', '91e69d90e5bf85e69c89e794a8efbc8c', 'e58d83e98791e695a3e5b0bde8bf98e5', 'a48de69da5e38082e783b9e7be8ae5ae', 'b0e7899be4b894e4b8bae4b990efbc8c', 'e4bc9ae9a1bbe4b880e9a5aee4b889e7', '99bee69dafe38082e5b291e5a4abe5ad', '90efbc8ce4b8b9e4b898e7949fefbc8c', 'e5b086e8bf9be98592efbc8ce69dafe8', '8eabe5819ce38082e4b88ee5909be6ad', '8ce4b880e69bb2efbc8ce8afb7e5909b', 'e4b8bae68891e580bee880b3e590ace3', '8082e9929fe9bc93e9a694e78e89e4b8', '8de8b6b3e8b4b5efbc8ce4bd86e684bf', 'e995bfe98689e4b88de5a48de98692e3', '8082e58fa4e69da5e59ca3e8b4a4e79a', '86e5af82e5af9eefbc8ce6839fe69c89', 'e9a5aee88085e79599e585b6e5908de3', '8082e99988e78e8be69894e697b6e5ae', 'b4e5b9b3e4b990efbc8ce69697e98592', 'e58d81e58d83e681a3e6aca2e8b091e3', '8082e4b8bbe4babae4bd95e4b8bae8a8', '80e5b091e992b1efbc8ce5be84e9a1bb', 'e6b2bde58f96e5afb9e5909be9858ce3', '8082e4ba94e88ab1e9a9ace38081e58d', '83e98791e8a398efbc8ce591bce584bf', 'e5b086e587bae68da2e7be8ee98592ef', 'bc8ce4b88ee5b094e5908ce99480e4b8', '87e58fa4e68481efbc81']
    
    str=s_b
    step=32
    str1=[str[i:i+step] for i in range(0,len(str),step)]
    if len(str1[len(str1)-1])<32:
      str1[len(str1)-1]=str1[len(str1)-1].ljust(32,'0')
    #print(str1)

    # AES-128
    print("***********************AES-128***********************")
    print("************************明文**************************")
    #print("PLAINTEXT:        %s" % binascii.hexlify(plaintext))
    #print("KEY:              %s" % binascii.hexlify(key128))
    print("明文存放在decrypto.txt中。")

    #print("\nCIPHER (ENCRYPT):")
    for KEYS in str1:
        KEYS=bytes().fromhex(KEYS)
        cipher128 = AES_enc(KEYS, key128)
        cipher=binascii.hexlify(cipher128)
        message128 = AES_dec(cipher128, key128)
        message=binascii.hexlify(message128)
        f = open('E:/0000桌面需要小文件/grade3/密码学课程设计/decrypto.txt','a')
        #can change the file path,'a'means to continue the last ones
        print(bytesToString(message),end='',file = f)
        #print(bytesToString(message),end='')
        f.close()
        #print(bytesToString(message))
        #print("------------------------------")        
        #print(binascii.hexlify(message128))
        #file_handle.close()
        
    

         #print("\nINVERSE CIPHER (DECRYPT):")
         #message128 = AES_dec(cipher128, key128)



    # hex->bytes->base64；
    with open('E:/0000桌面需要小文件/grade3/密码学课程设计/decrypto.txt','r',encoding='utf-8') as f:
        hexStr = f.read()
    #hexStr=s_b
    b_s=hexStr_to_str(hexStr)
    #message=base64.b64encode(b_s)
    #pic=base64.b64decode(message)


    #print(b_s)
    print('\n')
    print("************************解密**************************")
    f= open('E:/0000桌面需要小文件/grade3/密码学课程设计/message.txt','a',encoding='utf-8') 
    #can change the file path,'a'means to continue the last ones
    #b_s=bytes.fromhex(hexStr)
    #print(b_s)
    #print(type(b_s))
    #    f.write(pic)
    #print(f)
    print(b_s,end='',file=f)
    print("进制转换后生成文件message.txt。")
    f.close()


if __name__ == "__main__":
    test()



