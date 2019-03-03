Name
=============

lua-resty-ecdsa - ecdsa functions for LuaJIT

Status
======

This library is considered production ready.
This library is considered production ready.

Build status: [![Travis](https://travis-ci.org/aifeiasdf/lua-resty-ecdsa.svg?branch=master)](https://travis-ci.org/aifeiasdf/lua-resty-ecdsa)

Description
===========

This library requires an nginx build with OpenSSL,
the [ngx_lua module](https://github.com/openresty/lua-nginx-module), and [LuaJIT](http://luajit.org/luajit.html).


Synopsis
========

```lua
    # nginx.conf:

    lua_package_path "/path/to/lua-resty-ecdsa/lib/?.lua;;";

    server {
        location = /test {
            content_by_lua_file conf/test.lua;
        }
    }

    -- conf/test.lua:
    local cjson = require "cjson"
    local ec =require "resty.ecdsa"

    local suported_nids = ec:get_curves_id()
    ngx.say(cjson.encode(suported_nids))

    local pub, pri, err = ec:generate_ec_keys(415)
    if not pub then
        ngx.say('generate ec keys err: ', err)
    end

    ngx.say(pub)

    --[[
    -----BEGIN PUBLIC KEY-----
    MIIBSzCCAQMGByqGSM49AgEwgfcCAQEwLAYHKoZIzj0BAQIhAP////8AAAABAAAA
    AAAAAAAAAAAA////////////////MFsEIP////8AAAABAAAAAAAAAAAAAAAA////
    ///////////8BCBaxjXYqjqT57PrvVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwMVAMSd
    NgiG5wSTamZ44ROdJreBn36QBEEEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5
    RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9QIhAP////8AAAAA
    //////////+85vqtpxeehPO5ysL8YyVRAgEBA0IABHzFqWQ2vI78DuGJ0CWYR2CH
    tQfN6+6lixGBoetXl36Dlyu2P55Ni7uTd5iW9aUxPHhcIHg6oUR1+LyLuxcH5xI=
    -----END PUBLIC KEY-----
    ]]

    ngx.say(pri)
    --[[
    -----BEGIN PRIVATE KEY-----
    MIIBeQIBADCCAQMGByqGSM49AgEwgfcCAQEwLAYHKoZIzj0BAQIhAP////8AAAAB
    AAAAAAAAAAAAAAAA////////////////MFsEIP////8AAAABAAAAAAAAAAAAAAAA
    ///////////////8BCBaxjXYqjqT57PrvVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwMV
    AMSdNgiG5wSTamZ44ROdJreBn36QBEEEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg
    9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9QIhAP////8A
    AAAA//////////+85vqtpxeehPO5ysL8YyVRAgEBBG0wawIBAQQgqwUV1ZBm6a8C
    z9TlUJc2f/RWJJnbXdeoV/Tnf4bVIgahRANCAAR8xalkNryO/A7hidAlmEdgh7UH
    zevupYsRgaHrV5d+g5crtj+eTYu7k3eYlvWlMTx4XCB4OqFEdfi8i7sXB+cS
    -----END PRIVATE KEY-----
    ]]
    
    local public, err = ec:new({public_key = pub})
    if not public then
        ngx.say('new ec err: ', err)
        return ngx.exit(500)
    end

    local private, err = ec:new({private_key = pri})
    if not private then
        ngx.say('new ec err: ', err)
        return ngx.exit(500)
    end

    local sig, err = private:sign("hello")
    if err then
        ngx.say('sign with ec err: ', err)
        return ngx.exit(500)    
    end
    
    local flag, err = public:verify("hello", sig)
    if err then
        ngx.say('verify with ec err: ', err)
        return ngx.exit(500)    
    end

    ngx.say(flag)
```


Methods
=======

To load this library,

1. you need to specify this library's path in ngx_lua's [lua_package_path](https://github.com/openresty/lua-nginx-module#lua_package_path) directive. For example, `lua_package_path "/path/to/lua-resty-ecdsa/lib/?.lua;;";`.
2. you use `require` to load the library into a local Lua variable:

```lua
    local ec = require "resty.ecdsa"
```

get_curves_id
---
`syntax: curves = ec:get_curves_id()`

Return all curves supported.


generate_ec_keys
---
`syntax: public_key, private_key, err = ec:generate_ec_keys(nid)`

 Generate ecdsa public key and private key by specifying the curve of `nid`.

new
---
`syntax: obj, err = ec:new(opts)`

Creates a new ecdsa object instance by specifying an options table `opts`.

The options table accepts the following options:

* `public_key`
Specifies the public ec key.
* `private_key`
Specifies the private ec key.


sign
----
`syntax: signature, err = obj:sign(str)`

verify
------
`syntax: ok, err = obj:verify(str, signature)`


Performance
========



Author
======

河马大侠 (417424011@qq.com)

Copyright and License
=====================

This module is licensed under the MIT license.

Copyright (C) 2019-, by fei Ai (河马大侠)

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

See Also
========
* the ngx_lua module: http://wiki.nginx.org/HttpLuaModule