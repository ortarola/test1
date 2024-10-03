import threading
import time
from sdes_algorithm import encrypt, str_to_bin_list, bin_list_to_str

# 全局变量用于保存破解结果
found_key = None

# 生成所有可能的10位二进制密钥
def generate_keys():
    keys = []
    for i in range(1024):  # 2^10 = 1024，所有可能的10位密钥
        key = format(i, '010b')  # 生成10位二进制密钥
        keys.append(key)
    return keys

# 暴力破解线程函数，尝试一组密钥
def brute_force_worker(known_plaintext, known_ciphertext, key_list, thread_id):
    global found_key
    for key in key_list:
        if found_key:  # 如果其他线程已找到密钥，停止破解
            return
        key_bits = str_to_bin_list(key, 10)
        encrypted = encrypt(str_to_bin_list(known_plaintext, 8), key_bits)
        if bin_list_to_str(encrypted) == known_ciphertext:
            found_key = key
            print(f"线程{thread_id} 找到了正确的密钥: {key}")
            return

# 暴力破解函数，使用多线程
def brute_force_attack(known_plaintext, known_ciphertext, num_threads=4):
    global found_key
    found_key = None  # 重置全局变量
    keys = generate_keys()
    keys_per_thread = len(keys) // num_threads  # 每个线程处理的密钥数
    threads = []

    start_time = time.time()  # 开始时间戳

    # 创建并启动多个线程
    for i in range(num_threads):
        start = i * keys_per_thread
        end = start + keys_per_thread if i < num_threads - 1 else len(keys)
        thread = threading.Thread(target=brute_force_worker, args=(known_plaintext, known_ciphertext, keys[start:end], i))
        threads.append(thread)
        thread.start()

    # 等待所有线程结束
    for thread in threads:
        thread.join()

    end_time = time.time()  # 结束时间戳
    elapsed_time = end_time - start_time
    print(f"暴力破解完成，耗时 {elapsed_time:.2f} 秒")

    if found_key:
        return found_key, elapsed_time
    else:
        print("未找到匹配的密钥")
        return None, elapsed_time
