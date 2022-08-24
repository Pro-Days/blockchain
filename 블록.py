#블록
import struct
import hashlib
import ecdsa
import base58
import os


def fn_little_endian(string):
    flipped = "".join(reversed([string[i:i+2] for i in range(0,len(string), 2)]))
    return flipped

def fn_merkleRoot(txs):
    nodelist = txs
    while len(nodelist) > 1:
        newnodelist = []
        for idx in range(0, len(nodelist), 2):
            if idx != len(nodelist) - 1:
                nl, nr = nodelist[idx], nodelist[idx + 1]
            else:
                nl, nr = nodelist[idx], nodelist[idx]
            nl = fn_little_endian(nl)
            nr = fn_little_endian(nr)
            dhash = hashlib.sha256(hashlib.sha256(bytes.fromhex(nl + nr)).digest()).digest()
            dhash = fn_little_endian(dhash.hex())
            newnodelist.append(dhash)
        nodelist = newnodelist
    return nodelist[0]


txs = []
pubkey = ""
address = ""


privkey = os.urandom(32)


def fn_pubkey():
    _p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    _r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    _b = 0x0000000000000000000000000000000000000000000000000000000000000007
    _a = 0x0000000000000000000000000000000000000000000000000000000000000000
    _Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    _Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8


    secret = int(privkey.hex(), 16)


    curve_secp256k1 = ecdsa.ellipticcurve.CurveFp(_p, _a, _b)
    generator_secp256k1 = ecdsa.ellipticcurve.Point(curve_secp256k1, _Gx, _Gy)


    pubkey_point = generator_secp256k1 * secret



    global pubkey
    pubkey = '04' + '%064x' % pubkey_point.x() + '%064x' % pubkey_point.y()
    print("\n\n공공키:",pubkey)


def fn_address():
    
    hash1 = hashlib.sha256(bytes.fromhex(pubkey)).digest()
    hash2 = hashlib.new('ripemd160', hash1).digest()
    pubkeyversion = '00' + hash2.hex()
    check = hashlib.sha256(hashlib.sha256(bytes.fromhex(pubkeyversion)).digest()).digest()
    checksum = check.hex()[0:8]

    global address
    address = base58.b58encode(bytes.fromhex(pubkeyversion + checksum))
    print("\n\n주소:",address)


def fn_tx(tx_content1):
    version = struct.pack("<L", 2)
    tx_in_count = struct.pack("<B", 1)
    tx_in = []
    tx_out_count = struct.pack("<B", 1)
    tx_out = []
    lock_time = struct.pack("<L", 0)
    tx_content = struct.pack("<B", tx_content1)


    utxo_txid = "d85ceaa58fca1814ae50d168117a89ecd04628df6c9ba7ae5c62f8e9e92e8ca4"
    idx = 1
    adrr = "n4ow5W3UDR58ZudMngEyZkHwKDxyNs9fYP"
    wif = "cUAAsiDMhVboPVpgWPwpm5aGegvFvD85vJSz9kRTHpd2vwjJybKJ"


    txid = bytes.fromhex(fn_little_endian(utxo_txid))
    vout = struct.pack("<L", idx)
    scriptSig_ss = bytes.fromhex("")
    scriptSig_len = struct.pack("<B", len(scriptSig_ss))
    scriptSig = scriptSig_len + scriptSig_ss
    sequence = bytes.fromhex("FFFFFFFF")


    tx_in = txid + vout + scriptSig + sequence


    value = struct.pack("<Q",505000000)
    pubkeyhash = base58.b58decode(address).hex()[2:-8]
    scriptpubkey = "76a914" + pubkeyhash + "88ac"
    scriptpubkey_bytes = bytes.fromhex(scriptpubkey)


    tx_out = value + struct.pack("<B", len(scriptpubkey_bytes)) + scriptpubkey_bytes


    tx = version + tx_in_count + tx_in + tx_out_count + tx_out + lock_time + tx_content


    privkeyhash = base58.b58decode(wif).hex()[2:-10]


    hashed_tx = hashlib.sha256(hashlib.sha256(tx).digest()).digest()


    signingkey = ecdsa.SigningKey.from_string(bytes.fromhex(privkeyhash), curve = ecdsa.SECP256k1)
    SIG = signingkey.sign_digest(hashed_tx, sigencode = ecdsa.util.sigencode_der_canonize)


    scriptSig = struct.pack("<B", len(SIG)) + SIG + struct.pack("<B", 1) + struct.pack("<B", len(bytes.fromhex(pubkey)))


    scriptSig_ss = scriptSig
    scriptSig_len = struct.pack("<B",len(scriptSig_ss))
    scriptSig = scriptSig_len + scriptSig_ss


    tx_in = txid + vout + scriptSig + sequence


    tx = version + tx_in_count + tx_in + tx_out_count + tx_out + lock_time + tx_content
    txs.append(tx.hex())


    print("\n\ntx:",tx)
    print("\n")
    print("txs:",txs)


def fn_block():
    version = struct.pack("<L", 536870912)
    hashPreBlock = str('c2c74347a0ad6032e16003a0c37652c7ee2cab4010d9d4377fa2cb9730f2bdad')
    hashMerkRoot = str(fn_merkleRoot(txs))
    time = 'e7a0b45b'
    bits = str('207fffff')
    nounce = struct.pack("<L", 0)


    header = version.hex() + fn_little_endian(hashPreBlock) + fn_little_endian(hashMerkRoot) + time + fn_little_endian(bits) + nounce.hex()


    blockid = hashlib.sha256(hashlib.sha256(bytes.fromhex(header)).digest()).digest()
    print("\n\n" + fn_little_endian(blockid.hex()))




def command():
    command = input("\n\n명령: ")
    if command == "pubkey":
        fn_pubkey()

    elif command == "address" and pubkey != "":
        fn_address()

    elif command == "address" and pubkey == "":
        print("공공키가 존재하지 않습니다.")

    elif command == "tx" and address != "":
        tx_type = int(input("종류: (1: 거래, 2: 거래 예약, 3: 로그인)"))
        fn_tx(tx_type)

    elif command == "tx" and address == "":
        print("주소가 존재하지 않습니다.")

    elif command == "block" and txs != []:
        fn_block()

    elif command == "block" and txs == []:
        print("추가된 트랜잭션이 존재하지 않습니다.")


while True:
    command()