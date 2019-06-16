-- Copyright (C) Yichun Zhang (agentzh)
-- This file is modified version from https://github.com/openresty/lua-resty-websocket
-- The license is under the BSD license.
-- Modified by CoolDesert

local wbproto = require "websocket.protocol"
local _recv_frame = wbproto.recv_frame
local _send_frame = wbproto.send_frame
local str_lower = string.lower
local char = string.char
local str_find = string.find
local str_sub = string.sub
local str_format = string.format
local t_insert = table.insert
local t_concat = table.concat
local type = type
local setmetatable = setmetatable
local tostring = tostring

local httpd = require "http.httpd"
local crypt = require "skynet.crypt"
local base64 = crypt.base64encode
local sha1_bin = crypt.sha1

local _M = {}

local mt = { __index = _M }

local function parseFirstField(val)
    if not val then return end
    local index = str_find(val, ',', 1, true)
    return index and val:sub(1, index-1) or val
end

function _M.new(sock, opts)
    local read = sock.receive
    local write = sock.send
    local code, url, method, headers, body = httpd.read_request(read, 8192)
    local val = parseFirstField(headers.upgrade)
    if not val or str_lower(val) ~= "websocket" then
        return nil, "bad \"upgrade\" request header: " .. tostring(val)
    end

    val = parseFirstField(headers.connection)
    if not val or not str_find(str_lower(val), "upgrade", 1, true) then
        return nil, "bad \"connection\" request header"
    end

    local key = parseFirstField(headers["sec-websocket-key"])
    if not key then
        return nil, "bad \"sec-websocket-key\" request header"
    end

    local ver = parseFirstField(headers["sec-websocket-version"])
    if not ver or ver ~= "13" then
        return nil, "bad \"sec-websocket-version\" request header"
    end

    local resdata = {}
    t_insert(resdata , "HTTP/1.1 101 Switching Protocols")
    t_insert(resdata , "Upgrade: websocket")
    t_insert(resdata , "Connection: Upgrade")

    local sha1 = sha1_bin(key .. "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
    t_insert(resdata , "Sec-WebSocket-Accept: " .. base64(sha1))

    local protocols = parseFirstField(headers["sec-websocket-protocol"])
    if protocols then
        t_insert(resdata , "Sec-WebSocket-Protocol: " .. protocols)
    end

    t_insert(resdata , "\r\n")

    local response = t_concat(resdata , "\r\n")

    local ok, err = pcall(write, response)
    if not ok then
        return nil, "failed to send response header: " .. (err or "unknonw")
    end

    local max_payload_len, send_masked, timeout
    if opts then
        max_payload_len = opts.max_payload_len
        send_masked = opts.send_masked
        timeout = opts.timeout
    end

    return setmetatable({
        sock = sock,
        max_payload_len = max_payload_len or 65535,
        send_masked = send_masked,
    }, mt)
end

function _M.recv_frame(self)
    if self.fatal then
        return nil, nil, "fatal error already happened"
    end

    local sock = self.sock
    if not sock then
        return nil, nil, "not initialized yet"
    end

    local data, typ, err =  _recv_frame(sock, self.max_payload_len, true)
    if not data and not str_find(err, ": timeout", 1, true) then
        self.fatal = true
    end
    return data, typ, err
end


local function send_frame(self, fin, opcode, payload)
    if self.fatal then
        return nil, "fatal error already happened"
    end

    local sock = self.sock
    if not sock then
        return nil, "not initialized yet"
    end

    local bytes, err = _send_frame(sock, fin, opcode, payload,
                                   self.max_payload_len, self.send_masked)
    if not bytes then
        self.fatal = true
    end
    return bytes, err
end
_M.send_frame = send_frame


function _M.send_text(self, data)
    return send_frame(self, true, 0x1, data)
end

function _M.send_binary(self, data)
    return send_frame(self, true, 0x2, data)
end

function _M.send_close(self, code, msg)
    local payload
    if code then
        if type(code) ~= "number" or code > 0x7fff then
        end
        payload = char(code >> 8 & 0xff, code & 0xff) .. (msg or "")
    end
    return send_frame(self, true, 0x8, payload)
end

function _M.send_ping(self, data)
    return send_frame(self, true, 0x9, data)
end

function _M.send_pong(self, data)
    return send_frame(self, true, 0xa, data)
end

function _M.close(self)
    if self.fatal then
        return nil, "fatal error already happened"
    end

    local sock = self.sock
    if not sock then
        return nil, "not initialized"
    end

    if not self.closed then
        local bytes, err = _M.send_close(self)
        if not bytes then
            return nil, "failed to send close frame: " .. err
        end
    end

    return sock.close()
end



return _M
