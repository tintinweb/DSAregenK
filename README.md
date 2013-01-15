DSAregenK
=========

Recover the private key from signed DSA messages. (multiple signed messages, static coefficient 'k')

Dependencies:
=============

* [PyCrypto](https://www.dlitz.net/software/pycrypto/)



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

Code:

	from Crypto.Random import random
	from Crypto.PublicKey import DSA
	from Crypto.Hash import SHA
	
	from DSAregenK import DSAregenK
	
	import logging
	LOG = logging.getLogger('DSAregenK')
    LOG.setLevel(logging.DEBUG)
    logging.debug("-- on --")	
	
	privKey = DSA.generate(1024)		# generate new privkey
	pubKey  = privKey.publickey()		# extract pubkey

    a = DSAregenK(pubkey=pubkey)        # feed pubkey 

    a.add( (r1,s2),h1 )					# add signed messages
    a.add( (r2,s2),h2 )					# add signed messages
        
    for re_privkey in a.run(asDSAobj=True):     # reconstruct privatekey from samples (needs at least 2 signed messages with equal r param)
        if re_privkey.x in privkeys:            # compare regenerated privkey with one of the original ones (just a quick check :))
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
	

More Infos:
===========

* [DSA requirements for random k values](http://rdist.root.org/2010/11/19/dsa-requirements-for-random-k-value/)


