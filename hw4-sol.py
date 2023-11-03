import sys
# import mal1
import struct
import requests

import struct
import io

# Python implementation of Malicious Hashing from https://eprint.iacr.org/2014/694

__base__ = 'https://github.com/ajalt/python-sha1'
__license__ = 'MIT'


def _left_rotate(n, b):
    """Left rotate a 32-bit integer n by b bits."""
    return ((n << b) | (n >> (32 - b))) & 0xffffffff


def _process_chunk(chunk, h0, h1, h2, h3, h4):
    """Process a chunk of data and return the new digest variables."""
    assert len(chunk) == 64

    w = [0] * 80

    # Break chunk into sixteen 4-byte big-endian words w[i]
    for i in range(16):
        w[i] = struct.unpack(b'>I', chunk[i * 4:i * 4 + 4])[0]

    # Extend the sixteen 4-byte words into eighty 4-byte words
    for i in range(16, 80):
        w[i] = _left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)

    # Initialize hash value for this chunk
    a = h0
    b = h1
    c = h2
    d = h3
    e = h4

    for i in range(80):
        if 0 <= i <= 19:
            # Use alternative 1 for f from FIPS PB 180-1 to avoid bitwise not
            f = d ^ (b & (c ^ d))
            k = 0x5A827999
        elif 20 <= i <= 39:
            f = b ^ c ^ d
            k = 0x4EB9D7F7
        elif 40 <= i <= 59:
            f = (b & c) | (b & d) | (c & d)
            k = 0xBAD18E2F
        elif 60 <= i <= 79:
            f = b ^ c ^ d
            k = 0xD79E5877

        a, b, c, d, e = ((_left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff,
                         a, _left_rotate(b, 30), c, d)

    # Add this chunk's hash to result so far
    h0 = (h0 + a) & 0xffffffff
    h1 = (h1 + b) & 0xffffffff
    h2 = (h2 + c) & 0xffffffff
    h3 = (h3 + d) & 0xffffffff
    h4 = (h4 + e) & 0xffffffff

    return h0, h1, h2, h3, h4

class Mal1Hash(object):
    """A class that mimics that hashlib api and implements a maliciously modified SHA-1 algorithm."""

    name = 'python-mal1'
    digest_size = 20
    block_size = 64

    def __init__(self):
        # Initial digest variables
        self._h = (
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0,
        )

        # bytes object with 0 <= len < 64 used to store the end of the message
        # if the message length is not congruent to 64
        self._unprocessed = b''
        # Length in bytes of all data that has been processed so far
        self._message_byte_length = 0
        self.processed_chunks=list()
        self.hidden_states_record = list()
    
    def process_chunk(self,chunk, h0, h1, h2, h3, h4):
        self.processed_chunks.append(chunk)
        self.hidden_states_record.append((h0,h1,h2,h3,h4))
        return _process_chunk(chunk, h0, h1, h2, h3, h4)
    
    
    def update(self, arg):
        """Update the current digest.
        This may be called repeatedly, even after calling digest or hexdigest.
        Arguments:
            arg: bytes, bytearray, or BytesIO object to read from.
        """
        if isinstance(arg, (bytes, bytearray)):
            arg = io.BytesIO(arg)

        # Try to build a chunk out of the unprocessed data, if any
        chunk = self._unprocessed + arg.read(64 - len(self._unprocessed))

        # Read the rest of the data, 64 bytes at a time
        while len(chunk) == 64:
            self._h = self.process_chunk(chunk, *self._h)
            self._message_byte_length += 64
            chunk = arg.read(64)

        self._unprocessed = chunk
        return self

    def digest(self):
        """Produce the final hash value (big-endian) as a bytes object"""
        return b''.join(struct.pack(b'>I', h) for h in self._produce_digest())

    def hexdigest(self):
        """Produce the final hash value (big-endian) as a hex string"""
        return '%08x%08x%08x%08x%08x' % self._produce_digest(),self.processed_chunks

    def _produce_digest(self):
        """Return finalized digest variables for the data processed so far."""
        # Pre-processing:
        message = self._unprocessed
        message_byte_length = self._message_byte_length + len(message)

        # append the bit '1' to the message
        message += b'\x80'

        # append 0 <= k < 512 bits '0', so that the resulting message length (in bytes)
        # is congruent to 56 (mod 64)
        message += b'\x00' * ((56 - (message_byte_length + 1) % 64) % 64)

        # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
        message_bit_length = message_byte_length * 8
        message += struct.pack(b'>Q', message_bit_length)

        # Process the final chunk
        # At this point, the length of the message is either 64 or 128 bytes.
        h = self.process_chunk(message[:64], *self._h)
        if len(message) == 64:
            return h
        return self.process_chunk(message[64:], *h)



def mal1(data):
    """MAL-1 Hashing Function
    A maliciously modified SHA-1 hashing function implemented entirely in Python.
    Arguments:
        data: A bytes or BytesIO object containing the input message to hash.
    Returns:
        A hex MAL-1 digest of the input message.
    """
    return Mal1Hash().update(data).hexdigest()

TQDM_ON = False

def to_url_char(byte_value:int)->str:
    try_result = chr(byte_value)
    if try_result in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;=":
        return try_result
    return "%"+("%02x"%byte_value)

def try_construct(key_byte_cnt,query_str,hash_hidden_states):
    key_and_q_str = "1"*key_byte_cnt+query_str
    _hash_output,processed_chunks=mal1(key_and_q_str.encode(encoding="ascii"))
    param_string_to_append = "&get_file=hw4.pdf"
    p_str_to_append_bytes = param_string_to_append.encode("ascii")
    last_chunk = p_str_to_append_bytes
    total_size_in_byte = 64*len(processed_chunks)+len(param_string_to_append)
    last_chunk += b'\x80'
    last_chunk += b'\x00' * ((56 - (total_size_in_byte + 1) % 64) % 64)
    total_size_in_bit = 8*total_size_in_byte
    last_chunk += struct.pack(b'>Q', total_size_in_bit)
    h = _process_chunk(last_chunk[:64],*hash_hidden_states)
    if len(last_chunk)>64:
        h = _process_chunk(last_chunk[64:],*h)
    hash_hex_str = ""
    for hash_hidden_state_int64_num in h:
        hash_hex_str+=("%08x"%hash_hidden_state_int64_num)
    query_string_crafted = ""
    for p_chunk in processed_chunks:
        for byte1 in p_chunk:
            query_string_crafted+=to_url_char(byte1)
    query_string_crafted+=param_string_to_append
    query_string_crafted = query_string_crafted[key_byte_cnt:]
    res = url_without_param+"?"+"token="+hash_hex_str+"&"+query_string_crafted
    return res


if __name__=='__main__':
    url = "https://cse207b.nh.cryptanalysis.fun/hw4/api?token=17001485f42284b8c6775983fe83eaa1651e0d54&user=admin&get_file=kitten.jpg"
    if len(sys.argv)>=2:
        url = sys.argv[1]
    question_mark_i = url.find('?')
    url_without_param = url[:question_mark_i]
    param_str = url[question_mark_i+1:]
    first_and_i = param_str.find("&")
    token_param_str = param_str[:first_and_i]
    rest_of_q_str = param_str[first_and_i+1:]
    assert token_param_str.startswith("token=")

    token_hex_str = token_param_str[6:]
    hash_hidden_states=[0]*5
    for i in range(len(hash_hidden_states)):
        hash_hidden_states[i] = int(token_hex_str[8*i:8*i+8],16)
    
    kbcnt_range = range(64)
    if TQDM_ON:
        import tqdm
        kbcnt_range = tqdm.tqdm(kbcnt_range)
    for key_byte_cnt_try in kbcnt_range:
        url = try_construct(key_byte_cnt_try,rest_of_q_str,hash_hidden_states)
        response = requests.get(url)
        if len(response.content)>=100:
            print(url)