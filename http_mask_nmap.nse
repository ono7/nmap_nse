-- HEAD --

-- mask nmap User-Agent for stealth

local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"

-- The Rule Section --
portrule = shortport.http

-- The Action Section --
action = function(host, port)

    local uri = "/arcticfission.html"

    local options = {header={}}
    options['header']['User-Agent'] = "Mozilla/5.0 (compatible; ArcticFission)"

    local response = http.get(host, port, uri, options)

    if ( response.status == 200 ) then
        local title = string.match(response.body, "<[Tt][Ii][Tt][Ll][Ee][^>]*>ArcticFission ([^<]*)</[Tt][Ii][Tt][Ll][Ee]>")

        if ( title == "1.0" ) then
            return "Vulnerable"
        else
            return "Not Vulnerable"
        end
    end
end
