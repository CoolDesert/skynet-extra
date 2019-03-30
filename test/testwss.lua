local skynet = require "skynet"
local ws = require "websocket"

local function _handleAccepted(wsobj)
    skynet.error("accepted!!")
    wsobj:send_text("Hello Client!")
    while true do
        local data, type, err = wsobj:recv_frame()
        if type == "text" then
            wsobj:send_text(data)
        elseif type == "close" then
            skynet.error("recv client close!")
            wsobj:send_close()
            break
        end
        skynet.sleep(10)
    end
end

local function _handleConnected(wsobj)
    skynet.error("connected!!")
    local sum = 0
    while sum <= 10 do
        sum = sum + 1
        local data, type, err = wsobj:recv_frame()
        if type == "text" then
            skynet.error(data)
        elseif type == "close" then
            skynet.error("recv sever close!")
            wsobj:send_close()
            break
        end
        wsobj:send_text("foo " .. sum)
        skynet.sleep(10)
    end
end

skynet.start(function()
    --start server
    ws.listen({
        address = "0.0.0.0:8001",
        ssl_verify = true,
	    certfile = skynet.getenv("certfile") or "./test/server-cert.pem",
	    keyfile = skynet.getenv("keyfile") or "./test/server-key.pem"
    }, function (wsobj)
        skynet.fork(_handleAccepted, wsobj)
    end)
    --start client
    local wsobj = ws.connect({
        address = "wss://127.0.0.1:8001",
    })
    skynet.fork(_handleConnected, wsobj)
end)
