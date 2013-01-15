DSAregenK
=========

Recover the private key from signed DSA messages with weak coefficient 'k'. 
The coefficient is considered weak if 'k' is not unique and not totally random for all signed messages. 

Given two+ signed message hashes h(mA),h(mB) with signatures (rA,sA) and (rB,sB) where rA==rB and shared public_key 
coefficients (at least subprime q) one can reconstruct the private key that was used to sign these messages.


DSA Signature (r,s):

	r = g^k mod p mod q
	s = k-1 (H(m) + x*r) mod q
	
	x 	... private exponent
	y	... public exponent
	H()	... hash function
	m	... message
	g	... group generator
	p	... prime
	q	... subprime
	r,s	... digital signature components
	k	... per message secret number



Prerequesites:
=============

In order to reconstruct the private_key from signed DSA message you need to have:

* public_key parameters q [,y,g,p]
* a signed message consisting of: 
  * h(m) ... hashed message 
  * (r,s)... signature
* at least two messages with equal 'r'


Example:
=========

See example.py for another example using PyCrypto's DSA

Code:

	from Crypto.Random import random
	from Crypto.PublicKey import DSA
	from Crypto.Hash import SHA
	
	from DSAregenK import DSAregenK
	
	import logging
	LOG = logging.getLogger('DSAregenK')
	LOG.setLevel(logging.DEBUG)
	logging.debug("-- on --")    
	
	privkey = DSA.generate(1024)        # generate new privkey
	pubkey  = privkey.publickey()        # extract pubkey
	
	(r1,s1,h1)=(1104242600137843543695045937637417281163059700235L, 773789011712632302915807023844906579969862952621L, 857395097640348327305744475401170640455782257516L)
	(r2,s2,h2)=(1104242600137843543695045937637417281163059700235L, 684267073985982683308089132980132594478002742693L, 199515072252589500574227853970213073102209507294L)
	
	a = DSAregenK(pubkey=pubkey)        # feed pubkey 
	
	a.add( (r1,s1),h1 )                    # add signed messages
	a.add( (r2,s2),h2 )                    # add signed messages
	    
	for re_privkey in a.run(asDSAobj=True):     # reconstruct privatekey from samples (needs at least 2 signed messages with equal r param)
	    if re_privkey.x == privkey.x:           # compare regenerated privkey with one of the original ones (just a quick check :))
	        LOG.info( "Successfully reconstructed private_key: %s"%repr(re_privkey))
	    else:
	        LOG.error("Something went wrong :( %s"%repr(re_privkey))
            

Output:

	DEBUG:DSAregenK:-- Generating private key and signing 2 messages --
	DEBUG:DSAregenK: -- Attacking weak coefficient 'k' -- 
	DEBUG:DSAregenK:+ set: pubkey = <_DSAobj @0x239abe8 y,g,p(1024),q>
	DEBUG:DSAregenK:reconstructing PrivKey for Candidate r=1104242600137843543695045937637417281163059700235
	DEBUG:DSAregenK:privkey reconstructed: k=57220929329875084464606323767638590353588887144; x=11186518435742104824370011741638551120416928998;
	INFO:DSAregenK:Successfully reconstructed private_key: <_DSAobj @0x239aa80 y,g,p(1024),q,x,private>
	
	DEBUG:DSAregenK:+ set: pubkey = <_DSAobj @0x239acb0 y,g,p(1024),q>
	DEBUG:DSAregenK:reconstructing PrivKey for Candidate r=296706131631881635774685958204292247297893594734
	DEBUG:DSAregenK:privkey reconstructed: k=878142112336661011841646506798327227196069455298; x=1250118052601756091309216076961251244612791072328;
	INFO:DSAregenK:Successfully reconstructed private_key: <_DSAobj @0x239a940 y,g,p(1024),q,x,private>
	

Dependencies:
=============

* [PyCrypto](https://www.dlitz.net/software/pycrypto/)



More Infos:
===========

* [DSA requirements for random k values](http://rdist.root.org/2010/11/19/dsa-requirements-for-random-k-value/)


