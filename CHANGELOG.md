### Version 1.0.2, 2014-02-27

* Fix issue where WebServerUid#generate would fail if the network was unreachable; now we just fall back to
  `127.0.0.1`. (Guess where I'm writing this from?)

### Version 1.0.1, 2014-02-18

* Make `#to_s` and `#inspect` work reasonably, to make debugging a whole lot easier.

### Version 1.0.0, 2014-02-14

Initial release.
