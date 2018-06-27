=============
Standard File
=============

A library for accessing and interacting with a Standard File server.

.. raw:: html

   <p align="center">
      <a href="https://github.com/stephen-bunn/standardfile/blob/master/LICENSE" target="_blank"><img alt="License" src="https://img.shields.io/github/license/stephen-bunn/standardfile.svg"></a>
      <a href="https://travis-ci.org/stephen-bunn/standardfile" target="_blank"><img alt="Build Status" src="https://travis-ci.org/stephen-bunn/standardfile.svg?branch=master"></a>
      <a href="https://standardfile.readthedocs.io/" target="_blank"><img alt="Documentation Status" src="https://img.shields.io/readthedocs/standardfile.svg"></a>
      <a href="https://www.codacy.com/app/stephen-bunn/standardfile?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=stephen-bunn/standardfile&amp;utm_campaign=Badge_Grade"><img src="https://api.codacy.com/project/badge/Grade/235fcd8337b64a7496a0043191205f3e"/></a>
      <a href="https://saythanks.io/to/stephen-bunn" target="_blank"><img alt="Say Thanks!" src="https://img.shields.io/badge/Say%20Thanks-!-1EAEDB.svg"></a>
   </p>
   <p align="center">
      <a href="https://www.python.org/" target="_blank"><img alt="Made with: Python" src="https://forthebadge.com/images/badges/made-with-python.svg"></a>
   </p>


Usage
-----

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

| Following the basic worflow of authentication based synced storage systems, *currently* we don't allow a ``user`` to access their items through ``user.items`` if they are not authenticated and they have not run sync at least once.
| This is because we want to ensure the user has up to date items before they are allowed to modify anything.


Decrypting Items
~~~~~~~~~~~~~~~~

You can decrypt synced items by calling the ``user.decrypt`` method on an item.

>>> print(user.decrypt(user.items['d3866137-f7f6-4b98-8b34-43cae416472e']))
'testing'


Encrypting Items
~~~~~~~~~~~~~~~~

You can encrypt a new item by calling ``user.encrypt`` method with some content.

>>> item = user.encrypt('my content', 'my content type')
>>> print(item)
Item(uuid='3120ebf8-a6f7-4620-b99a-3e4a0233fcb1')

.. note:: However, this does not mean that the resulting item is synced or even setup to be synced.

The resulting item is currently only stored in memory.
In order to add the item to the sync, you can call the ``user.create`` method with the resulting item.

>>> user.create(item)


Now the created item exists locally and will be synced up to the remote whenever ``user.sync`` is called again.

----

You can use the shortcut method ``user.create_from`` with an existing file to encrypt and create the item with one call.

>>> item = user.create_from('/path/to/existing/file')


This item **is** currently setup to be synced and will be the next time ``user.sync`` is called.
