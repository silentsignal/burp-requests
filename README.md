Copy as requests plugin for Burp Suite
======================================

Copies selected request(s) as Python [requests][1] invocation.

Building
--------

 - Download the [Burp Extender API][2] and unpack it into `src`
 - Execute `ant`, and you'll have the plugin ready in `burp-requests.jar`

Dependencies
------------

 - JDK 1.7+ (tested on OpenJDK `1.7.0_85`, Debian/Ubuntu package: `openjdk-7-jdk`)
 - Apache ANT (Debian/Ubuntu package: `ant`)

License
-------

The whole project is available under MIT license, see `LICENSE.txt`.

  [1]: http://docs.python-requests.org/
  [2]: https://portswigger.net/burp/extender/api/burp_extender_api.zip
