`dl-verify`
===========

A project to build a small binary file which will download and verify the signature of that file against a given key.

Ideal useage:

`dl-verify --signature-ext='.asc' --signing-key=595E85A6B1B4779EA4DAAEC70B588DFF0527A9B7 https://github.com/krallin/tini/releases/download/v0.15.0/tini ./tini`

And upon successful completion a single file will exist on disk `./tini` which contains the [tini](https://github.com/krallin/tini) binary.