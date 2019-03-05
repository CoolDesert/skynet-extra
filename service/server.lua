local skynet = require "skynet"
local socket = require "skynet.socket"
local ssl = require "ssl"

local ssl_ctx

local function handleSocket(id)
    socket.start(id)

    local input = function(sz)
        local data = socket.read(id, sz)
        print("input:", #data)
        return data
    end

    local output = function(data)
        print("output:", #data)
        return socket.write(id, data)
    end

    local s = ssl.new(ssl_ctx, true, input, output)

    while true do
        local msg = s:read()
        if msg then
            skynet.error("client say: ", msg)
            s:write("bar")
        else
            socket.close(id)
            break
        end
    end
end

local function accept(id, ip)
    skynet.error("accept ", id, "from", ip)
    skynet.fork(handleSocket, id)
end

local function main()
    ssl_ctx = ssl.newctx("./test/server-cert.pem", "./test/server-key.pem", true)

    local listen_id = socket.listen("127.0.0.1", 8888);

    socket.start(listen_id, accept)
end

skynet.start(function ()
    print(pcall(main))
end)
