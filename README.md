# KZG setup based on Powers of Tau
This repository provides a way of loading Powers of Tau as [KZG](http://cacr.uwaterloo.ca/techreports/2010/cacr2010-10.pdf) setup parameters.
It specifically targets [the arkworks KZG implementation](https://crates.io/crates/ark-poly-commit).
Part of this repository is a binary that preprocesses Powers of Tau and produces an arkworks-ready file that is more performand to load.

Two functions are provided:
* `download_kzg_setup`: downloads the publicly available preprocessed parameters file, hosted by Anoma. 
* `load_kzg_setup`: loads the parameters from the parameters file 
