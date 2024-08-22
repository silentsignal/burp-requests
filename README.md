Copy as requests plugin for Burp Suite
======================================

Copies selected request(s) as Python [requests][1] invocation.

Building
--------

Execute `./gradlew build` and you'll have the plugin ready in `build/libs/burp-requests.jar`

License
-------

The whole project is available under MIT license, see `LICENSE.txt`,
except for the [Mjson library][2], where

> The source code is a single Java file. [...] Some of it was ripped
> off from other projects and credit and licensing notices are included
> in the appropriate places. The license is Apache 2.0.

  [1]: http://docs.python-requests.org/
  [2]: https://bolerio.github.io/mjson/
