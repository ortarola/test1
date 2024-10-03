# sdes_algorithm.py

# 置换函数，将输入 bits 根据 table 中的索引顺序进行置换
def permute(bits, table):
    # 检查索引是否超出 bits 的长度
    if max(table) >= len(bits):
        raise IndexError(f"置换表中的索引超出二进制列表的长度：max(table)={max(table)}, len(bits)={len(bits)}")
    return [bits[i] for i in table]

# 将字符串转化为二进制列表
def str_to_bin_list(s, size):
    if len(s) != size:
        raise ValueError(f"输入的二进制字符串长度应为 {size} 位，但得到 {len(s)} 位")
    try:
        # 确保字符串只包含 0 和 1
        int(s, 2)
    except ValueError:
        raise ValueError("输入的字符串应仅包含二进制位（0 和 1）")
    return [int(bit) for bit in s]

# 将二进制列表转为字符串
def bin_list_to_str(bits):
    return ''.join(str(bit) for bit in bits)

# 左移函数
def left_shift(bits, n):
    return bits[n:] + bits[:n]

# 密钥扩展函数
def key_schedule(key):
    # 标准 P10 和 P8 置换表（1-based 转 0-based）
    P10 = [2, 4, 1, 6, 3, 9, 0, 8, 7, 5]  # [3,5,2,7,4,10,1,9,8,6] → 0-based
    P8 = [5, 2, 6, 3, 7, 4, 9, 8]          # [6,3,7,4,8,5,10,9] → 0-based
    
    key = permute(key, P10)
    left_half, right_half = key[:5], key[5:]
    
    # 第一次左移
    left_half = left_shift(left_half, 1)
    right_half = left_shift(right_half, 1)
    # 生成子密钥 K1
    K1 = permute(left_half + right_half, P8)
    
    # 第二次左移
    left_half = left_shift(left_half, 2)
    right_half = left_shift(right_half, 2)
    # 生成子密钥 K2
    K2 = permute(left_half + right_half, P8)
    
    return K1, K2

# S盒代替函数
def sbox(input_bits, sbox_table):
    row = (input_bits[0] << 1) + input_bits[3]
    col = (input_bits[1] << 1) + input_bits[2]
    output = sbox_table[row][col]
    return [(output >> 1) & 1, output & 1]

# f 函数
def f(right, subkey):
    # 标准 EP 和 P4 置换表（1-based 转 0-based）
    EP = [3, 0, 1, 2, 1, 2, 3, 0]  # [4,1,2,3,2,3,4,1] → 0-based
    P4 = [1, 3, 2, 0]              # 标准 P4
    
    S0 = [
        [1, 0, 3, 2],
        [3, 2, 1, 0],
        [0, 2, 1, 3],
        [3, 1, 0, 2]
    ]
    S1 = [
        [0, 1, 2, 3],
        [2, 3, 1, 0],
        [3, 0, 1, 2],
        [2, 1, 0, 3]
    ]
    
    expanded_right = permute(right, EP)
    xor_result = [expanded_right[i] ^ subkey[i] for i in range(8)]
    left_sbox = sbox(xor_result[:4], S0)
    right_sbox = sbox(xor_result[4:], S1)
    return permute(left_sbox + right_sbox, P4)

# 单轮加密函数 fk
def fk(bits, subkey):
    left, right = bits[:4], bits[4:]
    return [left[i] ^ f(right, subkey)[i] for i in range(4)] + right

# 加密过程
def encrypt(plaintext, key):
    # 标准 IP 和 IP_inv 置换表（1-based 转 0-based）
    IP = [1, 5, 2, 0, 3, 7, 4, 6]        # [2,6,3,1,4,8,5,7] → 0-based
    IP_inv = [3, 0, 2, 4, 6, 1, 7, 5]    # [4,1,3,5,7,2,8,6] → 0-based
    
    K1, K2 = key_schedule(key)
    bits = permute(plaintext, IP)
    bits = fk(bits, K1)
    bits = bits[4:] + bits[:4]
    bits = fk(bits, K2)
    ciphertext = permute(bits, IP_inv)
    return ciphertext

# 解密过程
def decrypt(ciphertext, key):
    # 标准 IP 和 IP_inv 置换表（1-based 转 0-based）
    IP = [1, 5, 2, 0, 3, 7, 4, 6]        # [2,6,3,1,4,8,5,7] → 0-based
    IP_inv = [3, 0, 2, 4, 6, 1, 7, 5]    # [4,1,3,5,7,2,8,6] → 0-based
    
    K1, K2 = key_schedule(key)
    bits = permute(ciphertext, IP)
    bits = fk(bits, K2)
    bits = bits[4:] + bits[:4]
    bits = fk(bits, K1)
    plaintext = permute(bits, IP_inv)
    return plaintext

# sdes_algorithm.py

# 将字符串转换为ASCII编码的二进制列表
def ascii_to_bin_list(text):
    bin_list = []
    for char in text:
        bin_char = format(ord(char), '08b')  # 将每个字符转为8-bit二进制
        bin_list.append([int(bit) for bit in bin_char])
    return bin_list

# 将二进制列表转换回ASCII字符串
def bin_list_to_ascii(bin_list):
    text = ''
    for bin_char in bin_list:
        char = chr(int(''.join(str(bit) for bit in bin_char), 2))  # 将二进制转为字符
        text += char
    return text

# 修改后的加密算法，处理ASCII字符串
def encrypt_ascii(text, key):
    plaintext_bits_list = ascii_to_bin_list(text)
    ciphertext_bits_list = []
    
    for bits in plaintext_bits_list:
        ciphertext_bits = encrypt(bits, key)
        ciphertext_bits_list.append(ciphertext_bits)
    
    return bin_list_to_ascii(ciphertext_bits_list)

# 修改后的解密算法，处理ASCII字符串
def decrypt_ascii(text, key):
    ciphertext_bits_list = ascii_to_bin_list(text)
    plaintext_bits_list = []
    
    for bits in ciphertext_bits_list:
        plaintext_bits = decrypt(bits, key)
        plaintext_bits_list.append(plaintext_bits)
    
    return bin_list_to_ascii(plaintext_bits_list)
