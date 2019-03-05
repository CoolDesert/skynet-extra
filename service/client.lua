local skynet = require "skynet"
local socket = require "skynet.socket"
local ssl = require "ssl"

local ssl_ctx

local function handleSocket(id)

    local input = function()
        local data = socket.read(id)
        print("input:", #data)
        return data
    end

    local output = function(data)
        print("output:", #data)
        return socket.write(id, data)
    end

    local s = ssl.new(ssl_ctx, false, input, output)

    while true do
        s:write("foo")
        local msg = s:read()
        if (msg) then
            skynet.error("server say: ", msg)
            skynet.sleep(100)
        else
            socket.close(id)
            break
        end
    end

end

local function main()
    ssl_ctx = ssl.newctx("./test/client-cert.pem", "./test/client-key.pem", false)

    local id = socket.open("127.0.0.1", 8888)

    handleSocket(id)
end

skynet.start(function ()
    print(pcall(main))
    skynet.exit()
end)
