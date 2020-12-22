-- HEAD --
description = [[

find specific content in http response using sha hash to find vulnerable content
instead of matching patterns

nmap --script=./in_http_sha1 192.168.0.0/24 -p80,443 --open

-- TODO: add variable containing string to scan to make it more dynamic

ono7

]]

lisense = 'same as nmap see: https://nmap.org/book/man-legal.html'

local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local openssl = require "openssl"

-- The Rule Section --
portrule = shortport.http

-- The Action Section --
action = function(host, port)

    local uri = "/arcticfission.html"
    local response = http.get(host, port, uri)

    if ( response.status == 200 ) then
        local vulnsha1 = "984c6f159d5b5baba8fe23dfa5372d047ed1de2e"
        local sha1 = string.lower(stdnse.tohex(openssl.sha1(response.body)))

        if ( sha1 == vulnsha1 ) then
            return "Vulnerable"
        else
            return "Not Vulnerable"
        end
    end
end
