.. _gettings-tarted:

===============
Getting Started
===============

Installation and Setup
======================

Installing the package should be easy through `pipenv <https://docs.pipenv.org/>`_.

.. code-block:: bash

   $ pipenv install standardfile
   $ # or if you're old school...
   $ pip install standardfile

Or you can build and install the package from the git repo.

.. code-block:: bash

   $ git clone https://github.com/stephen-bunn/standardfile.git
   $ cd ./standardfile
   $ python setup.py install


Usage
=====

| Below is some documentation on how to do some basic things with this module.
| **Please keep in mind** that this module is still very alpha and some things are definitely not supported and other things are probably broken.


Logging In
~~~~~~~~~~

There are two basic ways to login.

>>> from standardfile import User
>>> user = User('user@example.com')
>>> print(user.authenticated)
False
>>> user.authenticate('password')
>>> print(user.authenticated)
True


or...

>>> user = User.login('user@example.com', 'password')
>>> print(user.authenticated)
True


If you use multi-factor authentication then simply provide the ``mfa`` keyword argument with the current code.

>>> user = User.login('user@example.com', 'password')
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/home/stephen-bunn/Git/standardfile/standardfile/user.py", line 228, in login
    user.authenticate(password, mfa=mfa)
  File "/home/stephen-bunn/Git/standardfile/standardfile/user.py", line 312, in authenticate
    raise exceptions.MFARequired("mfa code is required but not provided")
standardfile.exceptions.MFARequired: mfa code is required but not provided
>>> user = User.login('user@example.com', 'password', mfa='123456')
>>> print(user.authenticated)
True


If you are not trying to connect to the default standard notes sync server, then you can supply the ``host`` keyword with the desired host.

>>> user = User.login('user@example.com', 'password', host='https://sync.example.com')
>>> print(user.authenticated)
True


Syncing Items
~~~~~~~~~~~~~

Standard File works by essentially cloning the server's synced directory.
This is done through the simple ``sync`` command which clones the server items into the ``user.sync_dir`` folder.

>>> print(user.sync_dir)
/home/user/Git/standardfile/d79ca65d-3135-404c-a14d-e45b4226c101
>>> sync_results = user.sync()
>>> print(sync_results)
{'retrieved_items': [{'uuid': 'd3866137-f7f6-4b98-8b34-43cae416472e', 'content': '002:32d60ba576f418baf1173527c2e9c0c82cd3642885cbd48c2dc86e30ed5dfaeb:d3866137-f7f6-4b98-8b34-43cae416472e:9cab0dd683cac38b8fac8060a5d7f835:mrKYT+9jFsOuBO5Baa4jWA==', 'content_type': 'test', 'enc_item_key': '002:681be79d198eab9fb57695b74a522af8169ecf75f14eed8b588bb4a4a45c4e3e:d3866137-f7f6-4b98-8b34-43cae416472e:354d55bd7ac79d7a955372405a3c3a27:omJYXXy98pLj1JEGuSKB0/cc/Wu9bnNa5SjLSKsz6DwOxBnRFesNCqIImSxL5omN98LU4a5iXhqYwRPYp833Bc4UY5/Fexn0eSATMqZ/tRM=', 'auth_hash': None, 'created_at': '2018-06-07T23:08:48.023Z', 'updated_at': '2018-06-07T23:44:05.369Z', 'deleted': False}], 'saved_items': [], 'unsaved': [], 'sync_token': 'MjoxNTMwMTI4NjA2LjcwNTYyNDg=\n', 'cursor_token': None}


The retrieved items are accesible through the ``user.items`` dictionary.

>>> print(user.items)
{'d3866137-f7f6-4b98-8b34-43cae416472e': Item(uuid='d3866137-f7f6-4b98-8b34-43cae416472e')}


The synced items will be accessible locally in the ``user.sync_dir`` directory as a file named ``d3866137-f7f6-4b98-8b34-43cae416472e``.


Decrypting Items
~~~~~~~~~~~~~~~~

You can decrypt synced items by calling the ``user.decrypt`` function on an item.

>>> print(user.decrypt(user.items['d3866137-f7f6-4b98-8b34-43cae416472e']))
'testing'


Encrypting Items
~~~~~~~~~~~~~~~~

... TODO ...
