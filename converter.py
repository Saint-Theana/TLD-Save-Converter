import zlib
import argparse
import sys
import array
import base64
import re
from decimal import Decimal
import simplejson as json
import traceback
import struct

import array

class CLZF:
    HLOG = 14
    HSIZE = 1 << 14
    MAX_LIT = 1 << 5
    MAX_OFF = 1 << 13
    MAX_REF = (1 << 8) + (1 << 3)

    # Hashtable, that can be allocated only once
    _hash_table = [0] * HSIZE


    @staticmethod
    def decompress(input_bytes: bytes) -> bytes:
        # Starting guess, increase it later if needed
        output_byte_count_guess = len(input_bytes) * 2
        temp_buffer = bytearray(output_byte_count_guess)
        byte_count = CLZF.lzf_decompress(input_bytes, temp_buffer)

        # If byte_count is 0, then increase buffer and try again
        while byte_count == 0:
            output_byte_count_guess *= 2
            temp_buffer = bytearray(output_byte_count_guess)
            byte_count = CLZF.lzf_decompress(input_bytes, temp_buffer)

        return bytes(temp_buffer[:byte_count])

    @staticmethod
    def compress(input_bytes: bytes) -> bytes:
        # Starting guess, increase it later if needed
        output_byte_count_guess = len(input_bytes) * 2
        temp_buffer = bytearray(output_byte_count_guess)
        byte_count = CLZF.lzf_compress(input_bytes, temp_buffer)

        # If byte_count is 0, then increase buffer and try again
        while byte_count == 0:
            output_byte_count_guess *= 2
            temp_buffer = bytearray(output_byte_count_guess)
            byte_count = CLZF.lzf_compress(input_bytes, temp_buffer)

        return bytes(temp_buffer[:byte_count])

    @staticmethod
    def lzf_compress(input_bytes: bytes, output: bytearray) -> int:
        input_length = len(input_bytes)
        output_length = len(output)
    
        # Clear hash table
        CLZF._hash_table = [0] * CLZF.HSIZE
    
        iidx = 0
        oidx = 0
        lit = 0
    
        if input_length < 3:
            # Handle short input
            if input_length == 0:
                return 0
            output[oidx] = input_length - 1
            oidx += 1
            for i in range(input_length):
                output[oidx] = input_bytes[i]
                oidx += 1
            return oidx
    
        hval = (input_bytes[iidx] << 8) | input_bytes[iidx + 1]
    
        while True:
            if iidx < input_length - 2:
                hval = (hval << 8) | input_bytes[iidx + 2]
                # Fixed hash calculation to avoid negative shift
                hslot = ((hval << 5) ^ hval) & (CLZF.HSIZE - 1)
                reference = CLZF._hash_table[hslot]
                CLZF._hash_table[hslot] = iidx
    
                off = iidx - reference - 1
                if (off < CLZF.MAX_OFF and
                        iidx + 4 < input_length and
                        reference > 0 and
                        input_bytes[reference] == input_bytes[iidx] and
                        input_bytes[reference + 1] == input_bytes[iidx + 1] and
                        input_bytes[reference + 2] == input_bytes[iidx + 2]):
                    # Match found
                    len_ = 2
                    maxlen = min(input_length - iidx - len_, CLZF.MAX_REF)
    
                    if oidx + lit + 1 + 3 >= output_length:
                        return 0
    
                    while len_ < maxlen and input_bytes[reference + len_] == input_bytes[iidx + len_]:
                        len_ += 1
    
                    if lit != 0:
                        output[oidx] = lit - 1
                        oidx += 1
                        for i in range(-lit, 0):
                            output[oidx] = input_bytes[iidx + i]
                            oidx += 1
                        lit = 0
    
                    len_ -= 2
                    iidx += 1
    
                    if len_ < 7:
                        output[oidx] = (off >> 8) + (len_ << 5)
                        oidx += 1
                    else:
                        output[oidx] = (off >> 8) + (7 << 5)
                        oidx += 1
                        output[oidx] = len_ - 7
                        oidx += 1
    
                    output[oidx] = off & 0xFF
                    oidx += 1
    
                    iidx += len_ - 1
                    hval = (input_bytes[iidx] << 8) | input_bytes[iidx + 1]
    
                    hval = (hval << 8) | input_bytes[iidx + 2]
                    CLZF._hash_table[((hval << 5) ^ hval) & (CLZF.HSIZE - 1)] = iidx
                    iidx += 1
    
                    hval = (hval << 8) | input_bytes[iidx + 2]
                    CLZF._hash_table[((hval << 5) ^ hval) & (CLZF.HSIZE - 1)] = iidx
                    iidx += 1
                    continue
            elif iidx == input_length:
                break
    
            # One more literal byte to copy
            lit += 1
            iidx += 1
    
            if lit == CLZF.MAX_LIT:
                if oidx + 1 + CLZF.MAX_LIT >= output_length:
                    return 0
    
                output[oidx] = CLZF.MAX_LIT - 1
                oidx += 1
                for i in range(-lit, 0):
                    output[oidx] = input_bytes[iidx + i]
                    oidx += 1
                lit = 0
    
        if lit != 0:
            if oidx + lit + 1 >= output_length:
                return 0
    
            output[oidx] = lit - 1
            oidx += 1
            for i in range(-lit, 0):
                output[oidx] = input_bytes[iidx + i]
                oidx += 1
    
        return oidx

    @staticmethod
    def lzf_decompress(input_bytes: bytes, output: bytearray) -> int:
        input_length = len(input_bytes)
        output_length = len(output)

        iidx = 0
        oidx = 0

        while iidx < input_length:
            ctrl = input_bytes[iidx]
            iidx += 1

            if ctrl < (1 << 5):  # Literal run
                ctrl += 1

                if oidx + ctrl > output_length:
                    return 0

                for _ in range(ctrl):
                    output[oidx] = input_bytes[iidx]
                    oidx += 1
                    iidx += 1
            else:  # Back reference
                len_ = ctrl >> 5
                reference = oidx - ((ctrl & 0x1f) << 8) - 1

                if len_ == 7:
                    len_ += input_bytes[iidx]
                    iidx += 1

                reference -= input_bytes[iidx]
                iidx += 1

                if oidx + len_ + 2 > output_length:
                    return 0

                if reference < 0:
                    return 0

                output[oidx] = output[reference]
                oidx += 1
                reference += 1
                output[oidx] = output[reference]
                oidx += 1
                reference += 1

                for _ in range(len_):
                    output[oidx] = output[reference]
                    oidx += 1
                    reference += 1

        return oidx



class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(format(obj,"f"))  # 或者 return str(obj)
        return super().default(obj)

cache=[]

def transform_back(data):
    if isinstance(data, dict):
        for key in data.keys():
            if type(data[key]) == str:
                pass
            elif isinstance(data[key], dict):
                if key in cache:
                    transform_back(data[key])
                    data[key]=json.dumps(data[key],use_decimal=True,allow_nan=True,separators=(',', ':'))
                else:
                    transform_back(data[key])
            elif isinstance(data[key], list):
                if key in cache:
                    i=0
                    while i< len(data[key]):
                        transform_back(data[key][i])
                        if type(data[key][i]) == str or data[key][i] is None :
                            i=i+1
                            continue
                        data[key][i]=json.dumps(data[key][i],use_decimal=True,allow_nan=True,separators=(',', ':'))
                        i=i+1
                else:
                    transform_back(data[key])
            else:
                pass
                #print(type(data[key]))
    elif isinstance(data, list):
        i=0
        while i< len(data):
            item=data[i]
            if type(item) == str:
                pass
            elif isinstance(item, dict):
                transform_back(item)
            elif isinstance(item, list):
                transform_back(item)
            else:
                pass
                #print(type(item))
            i=i+1
    else:
        pass
        #print(type(data))
 
def transform(data):
    fuck=False
    if isinstance(data, dict):
        for key in data.keys():
            if type(data[key]) == str and len(data[key]) > 0 and data[key][0] == "{":
                in_data=json.loads(data[key],parse_float=Decimal,allow_nan=True)
                fuck=True
                shit=transform(in_data)
                data[key]=in_data
                cache.append(key)
            elif isinstance(data[key], dict):
                transform(data[key])
            elif isinstance(data[key], list):
                if transform(data[key]):
                    cache.append(key)
            else:
                pass
                #print(type(data[key]))
    elif isinstance(data, list):
        i=0
        while i< len(data):
            item=data[i]
            if type(item) == str and len(item) > 0 and item[0] == "{":
                in_data=json.loads(item,parse_float=Decimal,allow_nan=True)
                fuck=True
                transform(in_data)
                data[i]=in_data
            elif isinstance(item, dict):
                transform(item)
            elif isinstance(item, list):
                transform(item)
            else:
                pass
                #print(type(item))
            i=i+1
    else:
        pass
    return fuck

import re

import re

def remove_key_quotes_method1(text):
    """方法1: 使用正则表达式替换m_StatsDictionary中的key引号"""
    # 匹配m_StatsDictionary内容
    pattern = r'(\"m_StatsDictionary\":\{)(.*?)(\},\"m_NumBurntHousesInCoastal\")'
    
    def replace_keys(match):
        prefix = match.group(1)
        dict_content = match.group(2)
        suffix = match.group(3)
        
        # 去掉key的引号，保留value的引号
        # 匹配格式: "key":"value"
        key_pattern = r'\"(-?\d+)\":'
        dict_content = re.sub(key_pattern, r'\1:', dict_content)
        
        return prefix + dict_content + suffix
    
    result = re.sub(pattern, replace_keys, text)
    return result

# Example usage:
# json_string = 'your json string here'
# modified_json = replace_stats_dictionary(json_string)

def encode_data(raw_data):
    # 从文件读取JSON数据
    global cache
    with open('cache.txt', 'r', encoding='utf-8') as f:
        cache = json.load(f)
    parsed_data = json.loads(raw_data,parse_float=Decimal,allow_nan=True)
    transform_back(parsed_data)
    with open('back.txt', 'w') as f:
            f.write(json.dumps(parsed_data,allow_nan=True,  indent=2, ensure_ascii=False))
    for key in parsed_data["m_Dict"].keys():
        encoded=json.dumps(parsed_data["m_Dict"][key], use_decimal=True,allow_nan=True, separators=(',', ':'),ensure_ascii=False)
        if key == "global":
            encoded=remove_key_quotes_method1(encoded)
        encoded=encoded.encode('utf-8')
        dic=base64.b64encode(CLZF.compress(encoded))
        parsed_data["m_Dict"][key]=dic
    b=json.dumps(parsed_data, use_decimal=True,allow_nan=True, separators=(',', ':'),ensure_ascii=False)
    compressed = CLZF.compress(b.encode('utf-8'))
    print(len(compressed))
    #decompressed = CLZF.decompress(compressed)
    #print(len(decompressed))
    return compressed

def decode_data(encoded_data):
    decompressed = CLZF.decompress(encoded_data)
    print(len(decompressed))
    #compressed = CLZF.compress(decompressed)
    #print(len(compressed))
    #decompressed = CLZF.decompress(compressed)
    #print(len(decompressed))
    parsed_data = json.loads(decompressed,parse_float=Decimal,allow_nan=True)
    for key in parsed_data["m_Dict"].keys():
        encoded=parsed_data["m_Dict"][key]
        dic=json.loads(CLZF.decompress(base64.b64decode(encoded)),parse_float=Decimal,allow_nan=True)
        parsed_data["m_Dict"][key]=dic
    with open('raw.txt', 'w') as f:
            f.write(json.dumps(parsed_data, indent=2, ensure_ascii=False))
    transform(parsed_data)
    with open('cache.txt', 'w', encoding='utf-8') as f:
        json.dump(cache, f)
    return json.dumps(parsed_data, use_decimal=True,allow_nan=True,indent=2, ensure_ascii=False).encode("utf-8")

def main():
    # 设置命令行参数解析
    parser = argparse.ArgumentParser(description="文件编码/解码工具")
    parser.add_argument("-i", "--input", required=True, help="输入文件路径")
    parser.add_argument("-o", "--output", required=True, help="输出文件路径")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--encode", action="store_true", help="执行编码操作")
    group.add_argument("-d", "--decode", action="store_true", help="执行解码操作")
    
    args = parser.parse_args()
    
    try:
        # 读取输入文件 (二进制模式)
        with open(args.input, "rb") as f:
            input_data = f.read()
        
        # 执行编码或解码操作
        if args.encode:
            result = encode_data(input_data)
            action = "编码"
        else:
            result = decode_data(input_data)
            action = "解码"
        
        # 写入输出文件 (二进制模式)
        with open(args.output, "wb") as f:
            f.write(result)
        
        print(f"文件{action}成功! 输入: {args.input} -> 输出: {args.output}")
    
    except FileNotFoundError:
        print(f"错误: 输入文件不存在 - {args.input}")
        sys.exit(1)
    except Exception as e:
        error_trace = traceback.format_exc()
        print(f"处理过程中发生错误: {str(e)}\n")
        print("完整错误堆栈信息:")
        print(error_trace)
        sys.exit(1)

if __name__ == "__main__":
    main()





