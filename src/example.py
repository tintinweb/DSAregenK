from Crypto.Random import random
from Crypto.PublicKey import DSA
from Crypto.Hash import SHA

from DSAregenK import DSAregenK

import logging
LOG = logging.getLogger('DSAregenK')


def signMessage(privkey,msg,k=None):
    '''
    create DSA signed message
    @arg privkey ... privatekey as DSA obj
    @arg msg     ... message to sign
    @arg k       ... override random k
    '''
    k = k or random.StrongRandom().randint(1, privkey.q-1)
    # generate msg hash
    # sign the messages using privkey
    h = SHA.new(msg).digest()
    r,s = privkey.sign(h,k)
    return msg,h,(r,s),privkey.publickey()

if __name__=="__main__":
    LOG.setLevel(logging.DEBUG)
    logging.debug("-- on --")
    LOG.debug("-- Generating private key and signing 2 messages --")
    # Generate new DSA pub/private key pair
    secret_key = DSA.generate(1024)
    # choose a "random" - k :)  this time random is static in order to allow this attack to work
    k = random.StrongRandom().randint(1, secret_key.q-1)
    # sign two messages using the same k
    mA = signMessage(secret_key,"This is a signed message!",k)
    mB = signMessage(secret_key,"Another signed Message - I am the only one that may sign these messages :)",k)
    #
    # -- create another set of data --
    secret_key2 = DSA.generate(1024)
    #
    k = random.StrongRandom().randint(1, secret_key2.q-1)
    m5 =  signMessage(secret_key2,"xxx This is a signed message!",k) 
    m6 =  signMessage(secret_key2,"xxx Another signed Message - I am the only one that may sign these messages :)",k=0xffeeffee) 
    m7 =  signMessage(secret_key2,"xxx Another signed xxxMessage - I am the only one that may sign these messages :)",k)
    m8 =  signMessage(secret_key2,"xxx Another signed xxxxxxMessage - I am the only one that may sign these messages :)")  
    #
    # --- organize testset data ---
    #
    privkeys=[]     # just to keep track of our privkeys.. (for comparison, see below)
    privkeys.append(secret_key.x)
    privkeys.append(secret_key2.x)
    #
    data1 = []
    data1.append(mA)
    data1.append(mB)
    
    data2 = []
    data2.append(m5)
    data2.append(m6)
    data2.append(m7)
    data2.append(m8)
    
    datasets = [data1,data2]
    # ============================================================
    #
    #  Begin ATTACK Code :)
    #
    # ============================================================
    LOG.debug(" -- Attacking weak coefficient 'k' -- ")  
    for data in datasets:
        pubkey = pubkey=data[0][3]          # grab pubkey
        a = DSAregenK(pubkey=pubkey)        # feed DSAregen 
        for m,h,(r,s),pubkey in data:       # add sample data (message,hash,(signature)) to DSAregen
            a.add( (r,s),h )
            
        for re_privkey in a.run(asDSAobj=True):     # reconstruct privatekey from samples (needs at least 2 signed messages with equal r param)
            if re_privkey.x in privkeys:            # compare regenerated privkey with one of the original ones (just a quick check :))
                LOG.info( "Successfully reconstructed private_key: %s"%repr(re_privkey))
            else:
                LOG.error("Something went wrong :( %s"%repr(re_privkey))
            
