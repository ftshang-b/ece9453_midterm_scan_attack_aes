def bit_to_hex_full_string(bin_list):
    building_str = ""

    for i in range(0, len(bin_list), 8):
        building_str += bin_list_to_hex_characters(bin_list[i:i + 8])

    return building_str

def convert_to_str_bin_lst(bin_list):
    str_list = [None] * len(bin_list)
    for i in range(len(bin_list)):
        str_list[i] = str(bin_list[i])
    return [x for x in str_list]

# Need to convert bin_list to hexadecimal characters
def bin_list_to_hex_characters(bin_list):
    hex_table = {"0000": "0",
                 "0001": "1",
                 "0010": "2",
                 "0011": "3",
                 "0100": "4",
                 "0101": "5",
                 "0110": "6",
                 "0111": "7",
                 "1000": "8",
                 "1001": "9",
                 "1010": "A",
                 "1011": "B",
                 "1100": "C",
                 "1101": "D",
                 "1110": "E",
                 "1111": "F"}
    bin_str_1 = "".join(convert_to_str_bin_lst(bin_list[0:4]))
    bin_str_2 = "".join(convert_to_str_bin_lst(bin_list[4:]))
    input_str = hex_table[bin_str_1] + hex_table[bin_str_2]
    return input_str

def find_hamming_weight(list_of_bits):
    counter = 0
    for bit in list_of_bits:
        if bit == 1:
            counter += 1
    return counter

def binary_str_to_list(bin_str):
    bin_list_str = list(bin_str)
    for i in range(len(bin_list_str)):
        bin_list_str[i] = int(bin_list_str[i])
    return [x for x in bin_list_str]

def build_binary_list_of_affected_bytes(affected_indices, bin_list):
    bytes_affected = [-1] * len(affected_indices)
    for i in range(len(affected_indices)):
        bytes_affected[i] = bin_list[affected_indices[i]]
    return [x for x in bytes_affected]

def xor_function(t1, t2):
    return [x ^ y for x, y in zip(t1, t2)]

def find_affected_bits(output_bits, r_register_scan):
    for index in not_input_indices:
        if SCAN_TEST_PLAINTEXT[index] != r_register_scan[index] and index \
                not in output_bits:
            output_bits.append(index)

def find_byte_indices(textfile):
    byte_scan_chains = list()
    with open(textfile, "r", encoding="utf-8") as f:
        for line in f:
            byte_scan_chains.append(line.rstrip())
    f.close()
    output_list = list()
    for scan in byte_scan_chains:
        find_affected_bits(output_list, scan)
    return [x for x in output_list]

def decimal_to_bit_list_8_bits(num):
    bin_lst = [0] * 8
    curr_index = 0
    curr_power = 7
    curr_num = num
    while curr_num != 0:
        if curr_num >= pow(2, curr_power):
            bin_lst[curr_index] = 1
            curr_num -= pow(2, curr_power)
        curr_power -= 1
        curr_index += 1
    return [x for x in bin_lst]

# ===== Find Input Indices =====
input_scan_chains = []
with open("scan_chains/input_scanchains.txt", 'r', encoding='utf-16') as f:
    for line in f:
        input_scan_chains.append(line.rstrip())
f.close()

bit_num = 0
input_dict = {}
for scan_chain in input_scan_chains:
    for i in range(len(scan_chain)):
        if scan_chain[i] == "1":
            input_dict[bit_num] = i
            break
    bit_num += 1
# Print results of Input Bit Locations
tups = []
for bit_num in input_dict:
    tup = (input_dict[bit_num], bit_num)
    tups.append(tup)
tups.sort()
# tups used to print out scan output

sorted_input_dict = {}
for tup in tups:
    sorted_input_dict[tup[0]] = tup[1]

input_bits_all = []
for key in input_dict:
    input_bits_all.append(input_dict[key])

input_bits_all.sort()
not_input_indices = []

for i in range(256):
    if i not in input_bits_all:
        not_input_indices.append(i)
# ============================

SCAN_TEST_PLAINTEXT = \
    "0010000010001001011010000110101000000001000000000000010000110000000111001000000000000011101000010000010000000010100100110010001010000100100110010100010000000000101110100101100000001001100000001000010001101000000100101000010010100001010100001000011100000000"

byte_1_indices = find_byte_indices("scan_chains/byte1_scan_chain.txt")
byte_2_indices = find_byte_indices("scan_chains/byte2_scan_chain.txt")
byte_4_indices = find_byte_indices("scan_chains/byte4_scan_chain.txt")
byte_8_indices = find_byte_indices("scan_chains/byte8_scan_chain.txt")

byte_1_indices.sort()
byte_2_indices.sort()
byte_4_indices.sort()
byte_8_indices.sort()

affected_bytes = {}
for index in byte_1_indices:
    affected_bytes[index] = "bytes f00, f10, f20, f30"

for index in byte_2_indices:
    affected_bytes[index] = "bytes f03, f13, f23, f33"

for index in byte_8_indices:
    affected_bytes[index] = "bytes f02, f12, f22, f32"

for index in byte_4_indices:
    affected_bytes[index] = "bytes f01, f11, f21, f31"

sorted_affected_bytes = {}
for i in range(256):
    if i in not_input_indices:
        sorted_affected_bytes[i] = affected_bytes[i]

found_scan_chain = {}
for i in range(256):
    if i in input_bits_all:
        print("scan[" + str(i) + "]: input[" + str(sorted_input_dict[i]) + "]")
    else:
        print("scan[" + str(i) + "]: " + str(sorted_affected_bytes[i]))

print("Finding RK0...please wait.")

filename_2t = "scan_chains/aX_Y_2t.txt"
filename_2t_plus_1 = "scan_chains/aX_Y_2t_plus_1.txt"

bytes_2t = {}
bytes_2t_plus_1 = {}

for i in range(1, 17):
    bytes_2t[i] = None
    bytes_2t_plus_1[i] = None

curr_byte = 1
for col in range(4):
    for row in range(4):
        filename_2t_list = list(filename_2t)
        filename_2t_plus_1_list = list(filename_2t_plus_1)
        row_str = str(row)
        col_str = str(col)
        filename_2t_list[13] = row_str
        filename_2t_list[15] = col_str
        filename_2t_plus_1_list[13] = row_str
        filename_2t_plus_1_list[15] = col_str
        filename_2t_str = "".join(filename_2t_list)
        filename_2t_plus_1_str = "".join(filename_2t_plus_1_list)
        with open(filename_2t_str, 'r', encoding='utf-16') as f:
            bytes_2t[curr_byte] = [line.rstrip() for line in f]
        f.close()
        with open(filename_2t_plus_1_str, 'r', encoding='utf-16') as f:
            bytes_2t_plus_1[curr_byte] = [line.rstrip() for line in f]
        f.close()
        curr_byte += 1

for byte_num in range(1, 17):
    counter = 0
    reprocessed_list = list()
    for line in bytes_2t[byte_num]:
        if counter % 2 != 0:
            reprocessed_list.append(line)
        counter += 1
    bytes_2t[byte_num] = reprocessed_list

for byte_num in range(1, 17):
    counter = 0
    reprocessed_list = list()
    for line in bytes_2t_plus_1[byte_num]:
        if counter % 2 != 0:
            reprocessed_list.append(line)
        counter += 1
    bytes_2t_plus_1[byte_num] = reprocessed_list

#bytes 1, 6, 11, 16 -> f00, f10, f20, f30
#bytes 4, 5, 10, 15 -> f01, f11, f21, f31
#bytes 3, 8, 9, 14 -> f02, f12, f22, f32
#bytes 2, 7, 12, 13 -> f03, f13, f23, f33

affected_bytes_mapping = {1: list(byte_1_indices),
                          2: list(byte_2_indices),
                          3: list(byte_8_indices),
                          4: list(byte_4_indices),
                          5: list(byte_4_indices),
                          6: list(byte_1_indices),
                          7: list(byte_2_indices),
                          8: list(byte_8_indices),
                          9: list(byte_8_indices),
                          10: list(byte_4_indices),
                          11: list(byte_1_indices),
                          12: list(byte_2_indices),
                          13: list(byte_2_indices),
                          14: list(byte_8_indices),
                          15: list(byte_4_indices),
                          16: list(byte_1_indices)}

hamming_weight_table = {
    9: (226, 227),
    12: (242, 243),
    23: (122, 123),
    24: (130, 131)
}

bytes_a_for_2t_results = {}
bytes_a_for_2t_plus_1_results = {}
bytes_b_for_2t_results = {}
bytes_b_for_2t_plus_1_results = {}
rk0_possibilities = {}
for i in range(1, 17):
    bytes_a_for_2t_results[i] = None
    bytes_a_for_2t_plus_1_results[i] = None
    bytes_b_for_2t_results[i] = None
    bytes_b_for_2t_plus_1_results[i] = None
    rk0_possibilities[i] = None

# Step 1: Iterate through all the bytes, a_00 to a_33.
for current_a in range(1, 17):
    # Step 2a: Apply 2t for current a_ij byte
    two_t_scan_chains = bytes_2t[current_a]
    # Step 2b: Apply 2t+1 for current a_ij byte
    two_t_plus_1_scan_chains = bytes_2t_plus_1[current_a]
    # Step 3: Iterate from t = 0 to t = 127
    for t in range(128):
        lst1 = build_binary_list_of_affected_bytes(affected_bytes_mapping[
                                                       current_a],
                                                   binary_str_to_list(
                                                       two_t_scan_chains[t]))
        lst2 = build_binary_list_of_affected_bytes(affected_bytes_mapping[
                                                       current_a],
                                                   binary_str_to_list(
                                                       two_t_plus_1_scan_chains[t]))
        xor_result = xor_function(lst1, lst2)
        # Step 4: If XOR result is in hamming weight table, determine b1 and b2
        if find_hamming_weight(xor_result) in hamming_weight_table:
            b1, b2 = hamming_weight_table[find_hamming_weight(xor_result)]
            bytes_a_for_2t_results[current_a] = 2 * t
            bytes_a_for_2t_plus_1_results[current_a] = 2 * t + 1
            bytes_b_for_2t_results[current_a] = b1
            bytes_b_for_2t_plus_1_results[current_a] = b2
            break

# Step 5: Determine round key byte RK0 as b1 XOR a1, and b2 XOR a2
for byte in range(1, 17):
    if rk0_possibilities[byte] is None:
        rk0_possibilities[byte] = list()
    a_2t_bin_lst_1 = decimal_to_bit_list_8_bits(bytes_a_for_2t_results[byte])
    b_2t_bin_lst_1 = decimal_to_bit_list_8_bits(bytes_b_for_2t_results[byte])
    a_2t_bin_lst_2 = decimal_to_bit_list_8_bits(
        bytes_a_for_2t_plus_1_results[byte])
    b_2t_bin_lst_2 = decimal_to_bit_list_8_bits(
        bytes_b_for_2t_plus_1_results[byte])

    rk0_v1 = xor_function(a_2t_bin_lst_1, b_2t_bin_lst_1)
    rk0_v3 = xor_function(a_2t_bin_lst_1, b_2t_bin_lst_2)
    rk0_v2 = xor_function(a_2t_bin_lst_2, b_2t_bin_lst_2)
    rk0_v4 = xor_function(a_2t_bin_lst_2, b_2t_bin_lst_1)
    if rk0_v1 not in rk0_possibilities[byte]:
        rk0_possibilities[byte].append(rk0_v1)

    if rk0_v2 not in rk0_possibilities[byte]:
        rk0_possibilities[byte].append(rk0_v2)

    if rk0_v3 not in rk0_possibilities[byte]:
        rk0_possibilities[byte].append(rk0_v3)

    if rk0_v4 not in rk0_possibilities[byte]:
        rk0_possibilities[byte].append(rk0_v4)


# Step 6: Iterate through all possible RK0 values
all_possible_keys = []
for i in range(2):
    curr_byte_1 = rk0_possibilities[1][i]
    for j in range(2):
        curr_byte_2 = rk0_possibilities[2][j]
        for a in range(2):
            curr_byte_3 = rk0_possibilities[3][a]
            for b in range(2):
                curr_byte_4 = rk0_possibilities[4][b]
                for c in range(2):
                    curr_byte_5 = rk0_possibilities[5][c]
                    for d in range(2):
                        curr_byte_6 = rk0_possibilities[6][d]
                        for e in range(2):
                            curr_byte_7 = rk0_possibilities[7][e]
                            for f in range(2):
                                curr_byte_8 = rk0_possibilities[8][f]
                                for g in range(2):
                                    curr_byte_9 = rk0_possibilities[9][g]
                                    for h in range(2):
                                        curr_byte_10 = rk0_possibilities[10][h]
                                        for l in range(2):
                                            curr_byte_11 = \
                                                rk0_possibilities[11][l]
                                            for m in range(2):
                                                curr_byte_12 = \
                                                    rk0_possibilities[12][m]
                                                for n in range(2):
                                                    curr_byte_13 = \
                                                        rk0_possibilities[13][n]
                                                    for o in range(2):
                                                        curr_byte_14 = \
                                                            rk0_possibilities[14][o]
                                                        for p in range(2):
                                                            curr_byte_15 = \
                                                                rk0_possibilities[15][p]
                                                            for q in range(2):
                                                                curr_byte_16\
                                                                    = \
                                                                    rk0_possibilities[16][q]
                                                                all_possible_keys.append(curr_byte_1 + curr_byte_2 + curr_byte_3 + curr_byte_4 + curr_byte_5 + curr_byte_6 + curr_byte_7 + curr_byte_8 + curr_byte_9 + curr_byte_10 + curr_byte_11 + curr_byte_12 + curr_byte_13 + curr_byte_14 + curr_byte_15 + curr_byte_16)


hex_keys = []
for val in all_possible_keys:
    hex_keys.append(bit_to_hex_full_string(val))

from AES import aes_implementation
plaintext = "0BADC0DEDEADC0DE0BADC0DEDEADC0DE"
AESTest = aes_implementation.AesFromScratch()

aes_results = []
counter = 0

desired_key = None
for key in hex_keys:
    [tenRound, allkey] = AESTest.encrypt10round(plaintext, key)
    prettyCipherText = ""
    for byte in tenRound:
        prettyCipherText += byte
    if "7553F1319D628D075227785D730E7908" == prettyCipherText.upper():
        desired_key = key
        break
    counter += 1

print("Found RK0:", desired_key)