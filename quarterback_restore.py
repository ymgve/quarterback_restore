import argparse, io, os, re, struct, sys

def make_day_translation():
    dates = []
    for y in range(1978, 2100):
        for m in range(12):
            dpm = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)[m]
            if m == 1 and y % 4 == 0:
                dpm = 29
                    
            for d in range(dpm):
                dates.append((y, m + 1, d + 1))
                
    return dates
        
dates = make_day_translation()

def make_date(days, mins, ticks):
    if days > len(dates):
        return("BADDATE:%d" % days)
        
    y, m, d = dates[days]
    h = mins // 60
    mm = mins % 60
    s = ticks // 50
    ms = 20 * (ticks % 50)
    
    return "%04d-%02d-%02d %02d:%02d:%02d.%03d" % (y, m, d, h, mm, s, ms)
    
def make_next(s):
    numbers = re.findall(r'\d+', s)
    
    if not numbers:
        return None
    
    last_number = numbers[-1]
    incremented_number = str(int(last_number) + 1)

    s_reversed = s[::-1]
    last_number_reversed = last_number[::-1]
    incremented_number_reversed = incremented_number[::-1]
    
    s_reversed = s_reversed.replace(last_number_reversed, incremented_number_reversed, 1)
    
    return s_reversed[::-1]

def clean_cstring(s):
    if b"\x00" in s:
        return s.split(b"\x00")[0]
    else:
        return s

def read_cstring(f):
    s = b""
    while True:
        c = f.read(1)
        if c == b"\x00":
            break
            
        s += c
        
    return s
    
def make_safe(filename):
    res = ""
    for c in filename:
        if c in b" !#$%&'()+,-.0123456789;=@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{}~":
            res += chr(c)
        
    return res
    

class BitReader:
    def __init__(self, data):
        self.data = data
        self.index = 0
        
    def get_bit(self):
        res = (self.data[self.index >> 3] >> (self.index & 7)) & 1
        self.index += 1
        return res
        
    def get_bits(self, n):
        res = 0
        for i in range(n):
            res = res | (self.get_bit() << i)
            
        return res

class Decompressor:
    def __init__(self, data):
        self.br = BitReader(data)
        self.buffer_remaining = 0
        self.code_size = 9
        self.next_code = 258
        self.maxcode = (1 << self.code_size) - 1
        
    # the decompressor reads data in sequences of 8 code words at once, to be aligned with byte boundaries
    # when changing code word size, the remaining buffer is dropped and not used
    def get_code(self):
        if self.next_code > self.maxcode:
            self.code_size += 1
            if self.code_size == 16:
                self.maxcode = (1 << 16)
            else:
                self.maxcode = (1 << self.code_size) - 1
                
            #print("code size increased to", self.code_size, "dropping bits", self.buffer_remaining)
            self.br.get_bits(self.buffer_remaining)
            self.buffer_remaining = 0

        if self.buffer_remaining == 0:
            self.buffer_remaining = 8 * self.code_size
            
        self.buffer_remaining -= self.code_size
        return self.br.get_bits(self.code_size)
        
    def decompress(self, size):
        codes = dict([(x, bytes([x])) for x in range(256)])
        
        curr_entry = b""
        
        res = bytearray()
        
        while True:
            code = self.get_code()

            if code == 256:
                raise Exception("code 256 not handled yet!")
                
            elif code == 257:
                raise Exception("code 257 not handled yet!")
                
            if code not in codes:
                if code != self.next_code:
                    print("WARNING: Unexpected code", self.next_code, code)
                codes[code] = curr_entry + curr_entry[0:1]
                
            res += codes[code]
            
            if len(curr_entry) != 0 and self.next_code < (1 << 16):

                codes[self.next_code] = curr_entry + codes[code][0:1]
                self.next_code += 1
                
            curr_entry = codes[code]
            
            if len(res) >= size:
                return res
                
decrypt_table = (
	151,  32, 127,  11, 234, 174,  21, 110,  67, 163, 203, 154,  13,   1, 171, 213,
	103,  56, 130,  18, 177, 134, 188, 146,  48,  88, 211, 167, 111, 227, 140, 243,
	120,  43, 250,  62,  76, 182, 253, 149, 193, 181, 135,  36,  27, 229, 143,   0,
	162, 220,  52,  85, 192, 196,  83,  25, 159, 246, 152,   6, 199, 138,  71, 208,
	 16,   8, 125, 169, 148, 179,  93, 248, 108, 218, 186,  47,  29,  39, 145,  57,
	 44, 230,   3,  96, 216, 119, 205, 175,  35,  65, 254, 172, 183,  54,  10, 197,
	128,  73,  31, 201,  42,  15,  46, 224, 244, 129, 180, 123, 156, 236, 158, 106,
	101, 212, 126,  12,  89, 202, 217,  69,  40,  20, 113,  33, 223, 232, 195, 235,
	118, 141,  70, 238,  84,  79,  23,  64, 209, 133,  24, 222,  55,  94, 105, 207,
	 63,  66, 115, 241,  77,  61,  17,  92, 189, 198, 142,  75,  38,  98,  87, 170,
	 97, 252, 147,  60, 245,  82,  53,  74, 184, 247, 251, 221,  90, 155, 176, 237,
	242,  51,  81, 100, 239,  59, 166, 225,  72, 153,   7,  41, 190, 116,  34,   2,
	187, 132, 144, 114, 117, 204,  30,  22,  86,  80, 139, 104,   9, 215, 178,  91,
	122, 233,   5, 231, 161,  28, 214,  49, 137,  78, 168, 102,  26, 112,  19, 185,
	150, 226, 164, 255,  45,  68, 206,  37, 173, 124,   4,  50, 219, 157, 240, 131,
	249, 191, 210, 136,  99,  95, 200, 228, 165, 109, 160, 194,  58, 121,  14, 107)


def find_file_headers(diskdata):
    headers = []

    idx = 0
    while idx < len(diskdata) - 3:
        if diskdata[idx:idx+4] in (b"CFM\x90", b"FMRK"):
            marker = diskdata[idx:idx+4]
            filename = diskdata[idx+4:idx+36]
            filename = clean_cstring(filename)
            size = struct.unpack(">I", diskdata[idx+36:idx+40])[0]
            headers.append((idx, marker, filename, size))
            idx += 40
            
        else:
            idx += 1
           
    return headers


def decrypt_data(data, key):
    temptable = []
    for i in range(256):
        temptable.append(decrypt_table[(i - key) & 0xff])
        
    trans = bytes(temptable)
    
    return data.translate(trans)


def find_candidate_key(diskdata):
    cands = []
    for key in range(256):
        decrypted = decrypt_data(diskdata, key)
        if b"CFM\x90" in decrypted or b"FMRK" in decrypted:
            cands.append(key)
            
    if len(cands) == 0:
        print("ERROR: No candidate key found. This could happen if a file spans over multiple backup disks, or it uses an unsupported compression format")
        exit()
        
    if len(cands) >= 2:
        print("ERROR: Multiple candidate keys found. You have to manually pick one.")
        for key in cands:
            decrypted = decrypt_data(diskdata, key)
            headers = find_file_headers(decrypted)
            print("Files found with candidate key", key)
            for _, _, filename, size in headers:
                print("%10d %s" % (size, filename.decode("ascii", "ignore")))
            print("")
            
        exit()
        
    return cands[0]
    
def read_dir(bio, count, root):
    catalog = []
    for i in range(count):
        size, compsize, t_days, t_mins, t_ticks, fcount, prot, flags = struct.unpack(">IIHHHHBB", bio.read(18))
        fname = read_cstring(bio)
        comment = read_cstring(bio)
        
        fullnames = list(root)
        fullnames.append(fname)
        catalog.append((size, compsize, make_date(t_days, t_mins, t_ticks), fcount, prot, flags, fname, fullnames, comment))
        
        if flags & 0x80:
            catalog.extend(read_dir(bio, fcount, fullnames))
            
    return catalog

disksize = 512 * 11 * 2 * 80

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("filename")
    parser.add_argument("-s", "--singlefile", action="store_true", help="Do not look for and try to join together sequential files")
    parser.add_argument("-k", "--key", type=int, default=None, help="Decryption key, single byte decimal")
    parser.add_argument("--keysearch", action="store_true", help="Force search for decryption key")
    parser.add_argument("-c", "--catalog", action="store_true", help="Attempt to parse main catalog for the backup archive")
    parser.add_argument("-x", "--extract", help="Exctract files to destination directory")
    
    args = parser.parse_args()
    
    if args.key is None:
        diskdata = open(args.filename, "rb").read()
        if not args.keysearch:
            key = diskdata[0x0d]
        else:
            key = find_candidate_key(diskdata)

    else:
        key = args.key
        
    print("key", key)
    
    files = []
    if args.singlefile:
        files.append(args.filename)

    else:
        currfilename = args.filename
        while currfilename is not None and os.path.isfile(currfilename):
            files.append(currfilename)
            currfilename = make_next(currfilename)
            
    archivedata = bytearray()
    for currfilename in files:
        diskdata = open(currfilename, "rb").read()
        
        t_days, t_mins = struct.unpack(">II", diskdata[6:14])
        print("Adding disk image file", currfilename, "header", diskdata[0:4], "disk number", diskdata[4], "backup date", make_date(t_days, t_mins, 0))
        
        archivedata += diskdata[0x10:disksize]

    if args.extract:
        os.makedirs(args.extract, exist_ok=True)
        
    if args.catalog:
        buffersize, catsize = struct.unpack(">II", archivedata[0:8])
        
        if key != None:
            # file data might or might not be encrypted, quick and bad way to check
            if b"CFM\x90" not in archivedata and b"FMRK" not in archivedata:
                archivedata = decrypt_data(archivedata, key)
                
            else:
                catdata = archivedata[:0xcc + catsize]
                filedata = archivedata[0xcc + catsize:]
                archivedata = decrypt_data(catdata, key) + filedata
            
        bio = io.BytesIO(archivedata)

        _, _, version, _, numvols, compress, password, comment, name, volname = struct.unpack(">IIBBHB11s100s40s40s", bio.read(0xcc))
        password = clean_cstring(password)
        comment = clean_cstring(comment)
        name = clean_cstring(name)
        volname = clean_cstring(volname)
        print("Extra header: bufsize: 0x%x  catsize: 0x%x  version: %d  numvols: %d  compress: 0x%x  password %s comment %s name %s volname %s" % (buffersize, catsize, version, numvols, compress, password, comment, name, volname))

        count = struct.unpack(">H", bio.read(2))[0]
        catalog = read_dir(bio, count, [])

        testing = True
        for size, compsize, textdate, fcount, prot, flags, fname, fullname, comment in catalog:
            textpath = b"\\".join(fullname).decode("ascii", "ignore")
            print("%10d %10d %s %5d %02x %02x %s %s" % (size, compsize, textdate, fcount, prot, flags, textpath, comment))

            # directory, creating if it doesn't exist
            if flags & 0x80:
                if args.extract:
                    safepath = os.path.join(*[make_safe(x) for x in fullname])
                    fullpath = os.path.join(args.extract, safepath)

                    os.makedirs(fullpath, exist_ok=True)
                    
                continue
                
            if not testing:
                continue
                
            while bio.tell() % 4 != 0:
                bio.read(1)
               
            marker = bio.read(4)
            if marker not in (b"CFM\x90", b"FMRK"):
                raise Exception("ERROR unexpected marker", marker)
                
            fname2 = clean_cstring(bio.read(32))
            if fname != fname2:
                raise Exception("ERROR file names doesn't match", fname, fname2)

            size2 = struct.unpack(">I", bio.read(4))[0]
            if size != size2:
                raise Exception("ERROR file sizes doesn't match", size, size2)
                
            filedata = bio.read(compsize)
            if len(filedata) != compsize:
                print("ERROR didn't read all compressed data, skipping extraction of remaining files", len(filedata), compsize)
                testing = False
                continue
                
            if marker == b"CFM\x90" and size != 0:
                dec = Decompressor(filedata)
                filedata = dec.decompress(size)
                
            if len(filedata) > size:
                print("WARNING oversized file", len(filedata), size)
            
            # might be garbage data
            size3 = struct.unpack(">I", bio.read(4))[0]
            if size != size3:
                raise Exception("ERROR file sizes doesn't match", size, size3)
                
            if args.extract:
                of = open(fullpath, "wb")
                of.write(filedata[:size])
                of.close()

    else:
        if key != None:
            # file data might or might not be encrypted, quick and bad way to check
            if b"CFM\x90" not in archivedata and b"FMRK" not in archivedata:
                archivedata = decrypt_data(archivedata, key)
                
        for idx, marker, filename, size in find_file_headers(archivedata):
            print("%10d %s" % (size, filename.decode("ascii", "ignore")))
            
            if marker == b"CFM\x90" and size != 0:
                dec = Decompressor(archivedata[idx+40:])
                filedata = dec.decompress(size)
            else:
                filedata = archivedata[idx+40:idx+40+size]
                
            if len(filedata) > size:
                print("WARNING oversized file", len(filedata), size)
        
            if args.extract:
                # adding index offset as prefix to filenames to make sure they are all unique
                fullpath = os.path.join(args.extract, "%d_%s" % (idx, make_safe(filename)))
                of = open(fullpath, "wb")
                of.write(filedata[:size])
                of.close()
                
if __name__ == "__main__":
    main()
