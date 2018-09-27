#
#   DH.py : DH encryption/decryption and signatures
# 
#  Part of the Python Cryptography Toolkit
# 
# Distribute and use freely; there are no restrictions on further 
# dissemination and usage except those imposed by the laws of your 
# country of residence.  This software is provided "as is" without
# warranty of fitness for use or suitability for any purpose, express
# or implied. Use at your own risk or not at all. 
# 

from Crypto.PublicKey.pubkey import *
from Crypto.Util import number

##try:
##    from psyco.classes import *
##    import psyco
##    psyco.bind(number.getPrime)
##except ImportError:
##    pass

class error (Exception):
    pass

# Generate an DH key with N bits
def generate(bits, randfunc, progress_func=None):
    """generate(bits:int, randfunc:callable, progress_func:callable)

    Generate an DH key of length 'bits', using 'randfunc' to get
    random data and 'progress_func', if present, to display
    the progress of the key generation.
    """
    obj=DHobj()
    # Generate prime p
    if progress_func: progress_func('p\n')
    obj.p=bignum(getPrime(bits, randfunc))
    # Generate random number g
    if progress_func: progress_func('g\n')
    size=bits-1-(ord(randfunc(1)) & 63) # g will be from 1--64 bits smaller than p
    if size<1: size=bits-1
    while (1):
        obj.g=bignum(getPrime(size, randfunc))
        if obj.g<obj.p: break
        size=(size+1) % bits
        if size==0: size=4
    # Generate random number x
    if progress_func: progress_func('x\n')
    obj.gen_key(randfunc)
    return obj
    
def construct(tuple):
    """construct(tuple:(long,long)|(long,long,long,long))
             : DHobj
    Construct an DH key from a 2- or 4- tuple of numbers.
    """
    
    obj=DHobj()
    if len(tuple) not in [2, 3, 4]:
        raise error, 'argument for construct() wrong length' 
    for i in range(len(tuple)):
	field = obj.keydata[i]
	setattr(obj, field, tuple[i])
    return obj
    
class DHobj(pubkey):
    keydata=['p', 'g', 'y', 'x']

    def gen_key(self, randfunc):
        sp = long_to_bytes(self.p)
        bits = len(sp) * 8
        n = ord(sp[0])
        while n:
            n/=2
            bits += 1
        while (1):
            size=bits-1-ord(randfunc(1))
            # x will be from 1 to 256 bits smaller than p
            if size>2: break
        while (1):
            self.x=bignum(getRandomNumber(size, randfunc))
            if self.x<self.p: break
            size=(size+1) % bits
            if size==0: size=4
        self.y=pow(self.g, self.x, self.p)



    def _encrypt(self, M, K):
	if (not hasattr(self, 'x')):
	    raise error, 'Private key not available in this object'
	return self.y

    def _decrypt(self, M):
	if (not hasattr(self, 'x')):
	    raise error, 'Private key not available in this object'
        ax=pow(M[0], self.x, self.p)
	return ax

    def _sign(self, M, K):
        raise error, 'Signing not available in this object'

    def _verify(self, M, sig):
        raise error, 'Signing not available in this object'
        
    def size(self):
	"Return the maximum number of bits that can be handled by this key."
        bits, power = 0,1L
	while (power<self.p): bits, power = bits+1, power<<1
	return bits-1
	
    def hasprivate(self):
	"""Return a Boolean denoting whether the object contains
	private components."""
	if hasattr(self, 'x'): return 1
	else: return 0

    def publickey(self):
	"""Return a new key object containing only the public information."""
        return construct((self.p, self.g, self.y))

    def cansign(self):
        return 0
        
object=DHobj
