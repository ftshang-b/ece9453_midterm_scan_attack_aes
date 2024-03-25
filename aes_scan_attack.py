scan_chain_byte_1 =  \
    "0000000000000000000000000000000000000000000000000000000001000000000000000000000100001000000000000000000001000000000000000000000000000000000000100000000000000000000000000000001000000000000001000000000000000000000000000000000000000000000000000010000000000000"

scan_chain_byte_2 = "0000000000000000000000100000000000000000000000000000100000000000100000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000100000000000001000000001000000000000000000000000000000000000"

scan_chain_byte_3 = "0000100000000000000000000000000000000000000011000100000000000000010000000000000000000000000000000000000000000000000000000000000100000000001000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000"

scan_chain_byte_4 = "0000000000010000000000000000000000000000000000000000000000000000000000000000100000000000000010000000000000000000001000000000000000000000000000000000000000001000000000000000000000100000000000000000000000000000000000000000000001000100000000000000000000000000"

scan_chain_byte_5 = "0000000000000000000000001000000000000000000000000000000000000001000000000000000000000000000000000100000100000001000000001000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000"

scan_chain_byte_6 = "1000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000111000000000000011000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000"

scan_chain_byte_7 = "0000000000000000100000000000000000001000001000000000000000000000000000000000000000000000000000100000100000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000100000000000000000000000000000000000100000000000"

scan_chain_byte_8 = "0001000000000000000000000000000000100000000100100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000100000000000000000001000000000000000000000000000001000000000000000000"

scan_chain_byte_9 = "0000000000000000000100000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000010100000000000000000000010000000000000000000000001000000010000000000000000000"

scan_chain_byte_10 = "0000010000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000100000000000000000000000000001000000000000000000000000000000000000000000000000000000100000000000000000000000010000000100000000000000000000000000000010"

scan_chain_byte_11 = "0000000100000100000000000001000000000010000000000000000000000000000000000000000000000000000000000000000000001000000001000000000000000000000000000000000000000000000000000000000100000000000000000000000000000010000000000000000000000000000000000000000000000000"

scan_chain_byte_12 = "0000000000000000000000000000000000000000000000000000001000001000000000000100000000000100000000000000000010000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000001000000000000"

scan_chain_byte_13 = "0000000000000000000000010000000100000100000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000010000000010000000000000000000000000000000000000000000000010001000"

scan_chain_byte_14 = "0000000000000000000001000000000010000000000000000000000000000100000000000000000000000000000001000001000000000000000000000100000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000010000000000000000"

scan_chain_byte_15 = "0000000001000000000000000000000000000000010000000000000000000000000000010010000000000000000000000000000000010000000000000000000000000000000000000000000100000000000000000000000000000000000000000100000000000000000000000000001000000000000000000000000000000000"

scan_chain_byte_16 = "0000000000100000000000000000000001000000000000000000000010000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000001000000010010000000000000000000000000000000000000000000000000000000000000000000"


input_scan_chains = [scan_chain_byte_1, scan_chain_byte_2,
                     scan_chain_byte_3, scan_chain_byte_4,
                     scan_chain_byte_5, scan_chain_byte_6,
                     scan_chain_byte_7, scan_chain_byte_8,
                     scan_chain_byte_9, scan_chain_byte_10,
                     scan_chain_byte_11, scan_chain_byte_12,
                     scan_chain_byte_13, scan_chain_byte_14,
                     scan_chain_byte_15, scan_chain_byte_16]

byte_num = 1
input_dict = {}
# find input indices
for scan_chain in input_scan_chains:
    indices_of_byte = list()
    for i in range(len(scan_chain)):
        if scan_chain[i] == "1":
            indices_of_byte.append(i)
    input_dict[byte_num] = [x for x in indices_of_byte]
    byte_num += 1

for key in input_dict:
    print("Byte: " + str(key) + " Value: " + str(input_dict[key]))

input_bytes_all = []
for key in input_dict:
    for val in input_dict[key]:
        input_bytes_all.append(val)
input_bytes_all.sort()

not_input_indices = []
for i in range(256):
    if i not in input_bytes_all:
        not_input_indices.append(i)

#bytes 1, 6, 11, 16 -> f00, f10, f20, f30
#bytes 4, 5, 10, 15 -> f01, f11, f21, f31
#bytes 3, 8, 9, 14 -> f02, f12, f22, f32
#bytes 2, 7, 12, 13 -> f03, f13, f23, f33

def find_affected_bits(output_bits, r_register_scan):
    for index in not_input_indices:
        if scan_test_plaintext[index] != r_register_scan[index] and index \
                not in output_bits:
            output_bits.append(index)

scan_test_plaintext = "0010000010001001011010000110101000000001000000000000010000110000000111001000000000000011101000010000010000000010100100110010001010000100100110010100010000000000101110100101100000001001100000001000010001101000000100101000010010100001010100001000011100000000"

# BYTE 1
scan_test_1 = "0010000000001001011010000110101000000001000000000001010000010000001011001000000000000011101000010000011000000010100100110010001010000100100110010100010000100100111100100101100000000001101000000000010001101000000100100000110010100001010100101010011100000000"
scan_test_2 = "0010000010001011011010000110101000000001000000000001010000010000000111000000000000100011101000000000010000000010100100110010011010000100100110010100010000100000101110100101101000000001100000000000010001101000000101101000110010100001010100101000011100000000"
scan_test_3 = "0010000000001000011010000110101000000001000000000001010000110000000110101000000001100001101000000000010000000010100100110000011010000100100010110100010000000000111110100101100000001001100000001000010001101000000100100000110010100001010000001000011100000000"
scan_test_4 = "0010000010001001011010000100101000000001000000000001010000010000000011001000000100000011101000010000011000000010100100110010001010000100100110010100010000100100111110100101100000000001101000000000010001101000000100100000110010100001010100101000010100000000"
scan_test_5 = "0010000010001001011010000110101000000001000000000001010000010000001011001000000001000001101000010000011000000010100100110010001010000100100110010100010000100100111100100101100000000001100001000000010001101000000100100000110010100001010000101000011100000000"
scan_test_6 = "0010000000001010011010000100101000000001000000000000010000110000000010100000000001000001101000010000011001000010100100110010001010000100100010010100010000100100111110100101100000000001100000001000010001101000000100100000010010100001010000101000010100000000"
scan_test_7 = "0010000000001011011010000100101000000001000000000000010001010000000010001000000001100001101000000000011000000010100100110000011010000100100110010100010000000100101110100101100000001001101000000000010001101000000101101000010010100001010000001000010100000000"
scan_test_8 = "0010000010001001011010000100101000000001000000000001010000110000001111001000000001001001101000010000010000000010100100110000001010000100100110010100010000100000111100100101100000000001100000001000010001101000000101100000110010100001010000101000010100000000"

byte_1_register_r = [scan_test_1, scan_test_2, scan_test_3, scan_test_4,
                     scan_test_5, scan_test_6, scan_test_7, scan_test_8]

byte_1_indices = []
for scan in byte_1_register_r:
    find_affected_bits(byte_1_indices, scan)

# BYTE 2
scan_test_9 = "0010000010001001011010000110001000000001000000000000000000100000000101001001000000000010101000010000000000000010000100110010100010000100100100010100010000000000101110100001100010001001100000001010000001100000000100101100010000100001011100001000011000010000"
scan_test_10 = "0010000010001001011000000110001000000001000000010000000000100000000111001001000000000010110000010010000000000010000100110010000010000100100100010100010000000000101110100001100000001001100000001000000001101000000100101100010010100001111100001000011000010000"
scan_test_11 = "0010000010001001011010100110101000010001000000000000010000110000000111001000000000000011101100010010010000000010100100110010001010000100100100010100010000000000101010100101100000001001100000001000010001101000000100101000010010100001010100001000011100000000"
scan_test_12 = "0010000010001001011010000110101000000001000000010000000000100000000111001000000000000010101000010000010000000010000100110010101010000100100110010100011000000000101110100101100000001001100000001000010001100000000100101001010000100001110100001000011100000000"
scan_test_13 = "0010000010001001011010000110001000000001000000000000110000100000000101001000000000000010101000010000000000000010000100110010100010000100110100010100110000000000100110100001100000001001100000001010010001100000000100101100010000100001010100001000011100010000"
scan_test_14 = "0010000010001001011010000110001000010001000000010000000000100000000111001001000000000010101100010010010000000010000100110010100010000100100100010100011000000000101010100101100000001001100000001000010001100000001100101000010000100001010100001000011100010000"
scan_test_15 = "0010000010001001011000000110101000000001000000000000000000110000100111001000000000000010100000010010010000000010000100110010001010000100100110010100010000000000101110100101100000001001100000001000000001101000000100101100010010100001011100001000011000000000"
scan_test_16 = "0010000010001001011000000110001000010001000000010000010000100000000111001000000000000011100100010000010000000010100100110010100010000100110100010100111000000000100010100101100000001001100000001000100001100000000100101000010000100001011100001000011000010000"

byte_2_register_r = [scan_test_9, scan_test_10, scan_test_11, scan_test_12,
                     scan_test_13, scan_test_14, scan_test_15, scan_test_16]
byte_2_indices = []
for scan in byte_2_register_r:
    find_affected_bits(byte_2_indices, scan)

# BYTE 4
scan_test_25 = "0010000010000001011010000110101000000000000000000000010000110000000111001000000000010011101000010000010000000010101100100010001000000100000110010100010000000000101111100100100000001011100000001000011001101100000100101000010010100010010100001000011101100000"
scan_test_26 = "0010000010001001000010000010101000000000000000000000010000110000000111001000000000010011101000010000010000000010100100010010001000000100000110000100010000001000101111100101100000001001100000001000011001101100010100101000010010000010010100001000001101000000"
scan_test_27 = "0010000010000001010010000010101000000001100000000000010000110000000111001000000000010011101000010000010000000010100000010010001010000100100110000100010000000010001110100101100000101011000000001000011000101100000100101010010010100010010100001000001100100000"
scan_test_28 = "0010000010010001011010000110101000000001100000000000010000110000000111001000000000000011101000010000010000000010100100100010001000000100100110010100010000000000101111100101100000001011000000001000011000101100000100101000010010100000010100001000001100100000"
scan_test_29 = "0010000010001001010010000010101000000001100000000000010100110000000111001000000000010011101000010000010000000010100100000010001010000100100110010100010000000010001110100101100000001001000000001000011000101000000100001010010011100011010100001000001100000000"
scan_test_30 = "0010000010000001011010000110101000000000000000000000010000110000000111001000000000000011101000010000010000000010100100100010001000000100100110010100010000000000101111100101100000001011100000001000011001101100000100101000010010100100010100001000011100100000"
scan_test_31 = "0010000010000001000010000010101000000000000000000000010100110000000111001000100000000011101000010000010000000010100000000010001000000100100110010100010000000000101111100100100000001011100000001000011001101000010100001000010010000001010100001000001100100000"
scan_test_32 = "0010000010000001010010000010101000000001000000000000010100110000000111001000000000010011101010010000010000000010100100010010001000000100100110010100010000000010001111100101100000001011100000001000010001101100000100001010010010100010010100001000011100100000"

byte_4_register_r = [scan_test_25, scan_test_26, scan_test_27, scan_test_28,
                     scan_test_29, scan_test_30, scan_test_31, scan_test_32]

byte_4_indices = []
for scan in byte_4_register_r:
    find_affected_bits(byte_4_indices, scan)

# BYTE 8
scan_test_57 = "0010001010001001011010000110111000000001000000000000010000110000000111001000000000000011001000010000010000000000100100110010001011000100100110010100010011000000101110001101000000001000100000001000010101001001000100101000010010100001010100000000011100000101"
scan_test_58 = "0100001010001001011010000110111000000001000100000000010000110000000111001000000000000011101000010000010000000100100100110010001010000010100110010100010000010000101110100101100000001000100000001000010101001000000000101000000010100001000100000000011100000001"
scan_test_59 = "0100001010001001011010000110101000000001000000000000010000110000000111001000000000000011001000010000010000000000100100110010001010000100100110010000010010000000101110101101000000001000100000001000010001001000000100101000000010100001010101000000011100000000"
scan_test_60 = "0101001010001001011010000110111000000001000000000000010000110000000111001000000000000011001000010000010000000010100100110010001010000000100110010000010000000000101110100101100000001000100000001000010101101000000100101000000010100001010100000000011100000101"
scan_test_61 = "0110001010001001011010000110101000000001000000000000010000110000000111001000010010000011101000011000010000000100100100110010001010000110100110010000000000010000101110100101000000001000100100001000010001001000000000101000010010100001000100000000011100000100"
scan_test_62 = "0100001010001001011010000110111000000001000000100000010000110000000111001000010010000011001000011000010000000010100100110010001010000000100110010000000000000000101110100101000000001000100000001000010101101000000100101000000010100001010100000000011100000101"
scan_test_63 = "0000000010001001011010000110110000000001000000000000010000110000000111001000000000000011001000010000010000000000100100110010001010000000100110011100000000010000101110100101110000001001100000001000010101001000000000101000000010100001000100001000011100000001"
scan_test_64 = "0000000010001001011010000110111000100001000000000000010000110000000111001000010010000011101000011000010000000010100100110010001010000000100110010000000010000000101110101101100000001001100000001000010101001000000100101000000010100001010100001000011100000001"

byte_8_register_r = [scan_test_57, scan_test_58, scan_test_59, scan_test_60,
                     scan_test_61, scan_test_62, scan_test_63, scan_test_64]

byte_8_indices = []
for scan in byte_8_register_r:
    find_affected_bits(byte_8_indices, scan)

byte_1_indices.sort()
print(byte_1_indices)
print(len(byte_1_indices))
byte_2_indices.sort()
print(byte_2_indices)
print(len(byte_2_indices))
byte_4_indices.sort()
print(byte_4_indices)
print(len(byte_4_indices))
byte_8_indices.sort()
print(byte_8_indices)
print(len(byte_8_indices))