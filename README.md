OpenStack Swift middleware to fetch encryption root secret from Barbican service

Build from source and copy .tar to proxy node
---------------------------------------------

 (in a virtualenv):

```

git clone <github repo>
cd barbican_keymaster
python setup.py sdist

```

This will create a source tarball in sub-directory dist.

Upload the tarball to the server and install with:

```

sudo pip install castellan
sudo pip install barbican_keymaster-0.0.1.tar.gz

```

NOTE: on some distributions the installed middleware may not be readable in the
installed directory (e.g. /usr/local/lib/python<version>/dist-packages) and
you'll need to make sure it is world-readable.

...OR ... Git clone and install directly on proxy node
------------------------------------------------------

on proxy node:

```

git clone https://github.com/alistairncoles/barbican_keymaster
cd barbican_keymaster
sudo pip install -e .

```

Swift config changes
---------------------

Add the middleware to your Swift pipeline in the proxy file.
Edit /etc/swift/proxy-server.conf...

In section [pipeline:main], insert barbican_keymaster and encryption middleware
directly ahead of final proxy-logging (or replace keymaster with barbican_keymaster)

```

  ... barbican_keymaster encryption proxy-logging proxy-server

```

and add a section:

```

[filter:barbican_keymaster]
use = egg:barbican_keymaster#barbican_keymaster
key_id = <change me to key id from tail of secret_href e.g. 32a73b3a-2cd1-4eae-aa93-bdd729ccb568>
username = swift
password = swiftpass
project_name = swift_secret
user_domain_name=default
project_domain_name=default
auth_endpoint = http://<CHANGE_ME_TO_KEYSTONE_HOST>:5000/v3

```

NB change the key_id to the last past of the secret_href returned from
anc-barbican-setup.sh

NB change the keystone host in auth_endpoint

* restart swift proxy server
