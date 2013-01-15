'''
Created on 15.01.2013

@author: martin
'''
from Crypto.Random import random
from Crypto.PublicKey import DSA
from Crypto.PublicKey.pubkey import bignum,inverse
from Crypto.Hash import SHA
from Crypto.Util.number import bytes_to_long

import logging
LOG = logging.getLogger('DSAregenK')


class DSAregenK(object):
    def __init__(self,pubkey):
        self.samples = {}
        self.pubkey = pubkey
        LOG.debug("+ set: pubkey = %s"%pubkey)
    
    def add(self,signature,hash):
        '''
            sample is of format ( (r,s),hash(data), pubkey)
                       signature params,hashed_data
                       individual pubkey
        '''
        (r,s) = signature
        if not isinstance(hash,long):
            hash = bytes_to_long(hash)
        sample = bignum(r),bignum(s),bignum(hash)          #convert .digest()
        
        if not self.samples.has_key(r):
            self.samples[r]=[]
        
        
        self.samples[r].append(sample)
        #LOG.debug("+ added: sample = %s"%repr(sample))
    
    
    def run(self,asDSAobj=False):
        # find samples with equal r in signature
        for c in self._find_candidates():
            LOG.debug("[*] reconstructing PrivKey for Candidate r=%s"%c)
            (k,x) = self._attack(self.samples[c])
            if asDSAobj:
                yield self._construct_DSA((k,x))
            else:
                yield (k,x)
                
    def runBrute(self,asDSAobj=False,maxTries=None):
        for r,samples in self.samples.iteritems():
            LOG.debug("[*] bruteforcing PrivKey for r=%s"%r)
            for sample in samples:
                LOG.debug("[** - sample for r=%s]"%r)
                try:
                    (k,x) = self._brute_k(sample,maxTries=maxTries)
                    if asDSAobj:
                        yield self._construct_DSA((k,x))
                    else:
                        yield (k,x)
                except Exception, e:
                    logging.error(e.message)
                
    def _find_candidates(self):
        '''
            candidates have same r
        '''
        candidates = []
        for r, vals in self.samples.iteritems():
            if len(vals)>1: 
                candidates.append(r)
        return candidates
    
    
    def _attack(self,samples,q=None):
        '''
            samples = r,s,long(hash)
        '''
        q = q or self.pubkey.q
        
        rA,sA,hA = samples[0]
        
        k_h_diff = hA
        k_s_diff = sA
        
        first = True
        for r,s,hash in samples:
            if first:   
                first=False
                continue            #skip first one due to autofill
            k_h_diff -=hash
            k_s_diff -=s
        
        k = (k_h_diff)* inverse(k_s_diff,q) %q
        x = ((k*sA-hA)* inverse( rA,q) )% q

        LOG.debug("privkey reconstructed: k=%s; x=%s;"%(k,x))
        return k,x
    
    def _construct_DSA(self,privkey):
        k,x = privkey
        return DSA.construct([self.pubkey.y,
                              self.pubkey.g,
                              self.pubkey.p,
                              self.pubkey.q,
                              x])
        
    
    def _attack_single(self,hA,sigA,hB,sigB,q=None):
        q = q or self.pubkey.q
        rA,sA=sigA
        rB,sB=sigB
        k = (hA - hB)* inverse(sA -sB,q) %q
        x = ((k*sA-hA)* inverse( rA,q) )% q
        return k,x
    
    
    def _brute_k(self,sample,p=None,q=None,g=None,maxTries=None):
        '''
            sample = (r,s,h(m))
        '''
        # 1 < k < q
        p = p or self.pubkey.p
        q = q or self.pubkey.q
        g = g or self.pubkey.g
        
        r,s,h = sample
        
        k= 2
        while k< q-1:
            if maxTries and k >= maxTries+2:
                break
            # calc r = g^k mod p mod q
            if r == pow(g,k,p)%q: 
                x = ((k*s-h)* inverse( r,q) )% q
                return k,x
            k+=1        #next k
        raise Exception("Max tries reached! - %d/%d"%(k-2,maxTries))

            
if __name__=="__main__":
    import timeit
    code = '''
    q=1265463802023530275326394511026959111076549652869
    g=84281203019815261389723351787997895766686782784042902057749572710486802455287943930039236293081120645856643138985466753439864717645302485601757623822904847629009405411053311508933914054126213326746234712047394770958935994092610093437274339721778386724204641098513873421986583220412010274767817275626531483349
    k =155862235091383259018358242245666680486589863514
    p = 89884656743115801565356913078863255627534578994836271275156367742905551420240587387886756001391175742871349954773362607747817656666949585098232008455275447903314834915566557308039663748037501217455176261144977713143895613500344330528376806523498586766563054718557062834734452717511314328898484995977406013223
    
    r,s =  (808569543022789887955253071826070582321521360626L, 144740468085989213718785495673981993705197878815L)
    pow(g,k,p)%q
    '''
    trials = 2**15
    print trials," trials =>", timeit.timeit(code,number=trials),"s "