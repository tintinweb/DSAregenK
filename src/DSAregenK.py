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
        LOG.debug("+ added: sample = %s"%repr(sample))
    
    
    def run(self,asDSAobj=False):
        # find samples with equal r in signature
        for c in self._find_candidates():
            LOG.debug("reconstructing PrivKey for Candidate r=%s"%c)
            (k,x) = self._attack(self.samples[c])
            if asDSAobj:
                yield self._construct_DSA((k,x))
            else:
                yield (k,x)
    
    def _find_candidates(self):
        '''
            candidates have same r
        '''
        candidates = []
        for r, vals in self.samples.iteritems():
            if len(vals)>1: 
                LOG.debug("+ found candidate: %s"%r)
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