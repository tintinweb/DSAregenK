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

to be filled


More Infos:
===========

* [DSA requirements for random k values](http://rdist.root.org/2010/11/19/dsa-requirements-for-random-k-value/)


