local skynet = require "skynet"
local server = require "websocket.server"
local client = require "websocket.client"

local socket = require "skynet.socket"
local sockethelper = require "http.sockethelper"
local tls = require "http.tlshelper"

local function _newctx(certfile, keyfile)
    local ctx = tls.newctx()
    if certfile and keyfile then
        ctx:set_cert(certfile, keyfile)
    end
    return ctx
end

local function _newserver(ctx, id, opts)
    local sock
    if opts.ssl_verify then
        local tls_ctx = tls.newtls("server", ctx)
        local init = tls.init_responsefunc(id, tls_ctx)
        local close = tls.closefunc(tls_ctx)
        init()
        sock = {
            receive = tls.readfunc(id, tls_ctx),
            send = tls.writefunc(id, tls_ctx),
            close = close
        }
    else
        sock = {
           receive = sockethelper.readfunc(id),
           send = sockethelper.writefunc(id),
           close = function () sockethelper.close(id) end
        }
    end
    return server.new(sock)
end

local function _newclient(ctx, id, opts)
    local sock
    if opts.ssl_verify then
        local tls_ctx = tls.newtls("client", ctx)
        local init = tls.init_requestfunc(id, tls_ctx)
        local close = tls.closefunc(tls_ctx)
        init()
        sock = {
            receive = tls.readfunc(id, tls_ctx),
            send = tls.writefunc(id, tls_ctx),
            close = close
        }
    else
        sock = {
           receive = sockethelper.readfunc(id),
           send = sockethelper.writefunc(id),
           close = function () sockethelper.close(id) end
        }
    end
    return client.new(sock, opts)
end

local M = {}

function M.listen(opts, callback)
    local ctx
    if opts.ssl_verify then
        assert(opts.certfile)
        assert(opts.keyfile)
        ctx = _newctx(opts.certfile, opts.keyfile)
    else
        ctx = _newctx()
    end
    local address = assert(opts.address)
    local id = assert(socket.listen(address, nil, opts.backlog))
    skynet.error("Listening ".. address .. ", tls/ssl: " .. (opts.ssl_verify and "true" or "false"))
    socket.start(id , function(fd, addr)
        socket.start(fd)
        callback(_newserver(ctx, fd, opts))
    end)
end

function M.connect(opts, ctx)
    ctx = ctx or _newctx(opts.certfile, opts.keyfile)
    local address = assert(opts.address)
    local head, host, port, path = address:match("(wss?)://([^:/]+):?(%d*)/?(.*)") 
    opts.ssl_verify = false
    opts.path = path
    if head == "wss" then
        opts.ssl_verify = true
    elseif head ~= "ws" then
        return nil, "Must be websocket"
    end
    port = tonumber(port) or (opts.ssl_verify and 443 or 80)
    local id, err = socket.open(host, port)
    if not id then
        return nil, err
    end
    return _newclient(ctx, id, opts), ctx
end

return M
