-- Copyright (C) Yichun Zhang (agentzh)
-- This file is modified version from https://github.com/openresty/lua-resty-websocket
-- The license is under the BSD license.
-- Modified by CoolDesert

-- FIXME: this library is very rough and is currently just for testing
--        the websocket server.

local wbproto = require "websocket.protocol"
local _recv_frame = wbproto.recv_frame
local _send_frame = wbproto.send_frame
local char = string.char
local str_find = string.find
local rand = math.random
local setmetatable = setmetatable
local type = type
local tconcat = table.concat

local httpd = require "http.httpd"
local internal = require "http/internal"
local urllib = require "http.url"
local crypt = require "skynet.crypt"
local base64 = crypt.base64encode
local sha1_bin = crypt.sha1

local _M = {}

local mt = { __index = _M }

function _M.new(sock, opts)
    
    local read = sock.receive
    local write = sock.send
 
    local address = assert(opts.address)
    local path = assert(opts.path)

    local max_payload_len = opts.max_payload_len
    local proto_header, origin_header

    local protos = opts.protocols
    if protos then
        if type(protos) == "table" then
            proto_header = "\r\nSec-WebSocket-Protocol: " .. tconcat(protos, ",")
        else
            proto_header = "\r\nSec-WebSocket-Protocol: " .. protos
        end
    end

    local origin = opts.origin
    if origin then
        origin_header = "\r\nOrigin: " .. origin
    end

    -- do the websocket handshake:

    local bytes = char(rand(256) - 1, rand(256) - 1, rand(256) - 1,
                       rand(256) - 1, rand(256) - 1, rand(256) - 1,
                       rand(256) - 1, rand(256) - 1, rand(256) - 1,
                       rand(256) - 1, rand(256) - 1, rand(256) - 1,
                       rand(256) - 1, rand(256) - 1, rand(256) - 1,
                       rand(256) - 1)

    local key = base64(bytes)
    local req = "GET " .. path .. " HTTP/1.1"
                .. "\r\nUpgrade: websocket"
                .. "\r\nHost: " .. address
                .. "\r\nSec-WebSocket-Key: " .. key
                .. (proto_header or "")
                .. "\r\nSec-WebSocket-Version: 13"
                .. (origin_header or "")
                .. "\r\nConnection: Upgrade\r\n\r\n"

    local ok, err = pcall(write, req)
    if not ok then
        return nil, "failed to send the handshake request: " .. err
    end

    -- parse server response

    local tmpline = {}
    local body = internal.recvheader(read, tmpline, "")
    if not body then
        return nil, "failed to recv response" .. socket.socket_error
    end

	local statusline = tmpline[1]
	local code, info = statusline:match "HTTP/[%d%.]+%s+([%d]+)%s+(.*)$"
	code = assert(tonumber(code))

	local header = internal.parseheader(tmpline,2,recvheader or {})
	if not header then
		return nil, "Invalid HTTP response header"
	end

	local length = header["content-length"]
	if length then
		length = tonumber(length)
	end
	local mode = header["transfer-encoding"]
	if mode then
		if mode ~= "identity" and mode ~= "chunked" then
			error ("Unsupport transfer-encoding")
		end
	end

	if mode == "chunked" then
		body, header = internal.recvchunkedbody(read, nil, header, body)
		if not body then
			error("Invalid response body")
		end
	else
		-- identity mode
		if length then
			if #body >= length then
				body = body:sub(1,length)
			else
				local padding = read(length - #body)
				body = body .. padding
			end
		else
			-- no content-length, read all
		end
    end
    
    --TODO :: verify server Sec-WebSocket-Accept

    return setmetatable({
        sock = sock,
        max_payload_len = max_payload_len or 65535,
        send_unmasked = send_unmasked,
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

    local data, typ, err =  _recv_frame(sock, self.max_payload_len, false)
    if not data and not str_find(err, ": timeout", 1, true) then
        self.fatal = true
    end
    return data, typ, err
end

local function send_frame(self, fin, opcode, payload)
    if self.fatal then
        return nil, "fatal error already happened"
    end

    if self.closed then
        return nil, "already closed"
    end

    local sock = self.sock
    if not sock then
        return nil, "not initialized yet"
    end

    local bytes, err = _send_frame(sock, fin, opcode, payload, self.max_payload_len, true)
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

local function send_close(self, code, msg)
    local payload
    if code then
        if type(code) ~= "number" or code > 0x7fff then
            return nil, "bad status code"
        end
        payload = char(((code >> 8) & 0xff), (code & 0xff)) .. (msg or "")
    end

    --print("sending the close frame")

    local bytes, err = send_frame(self, true, 0x8, payload)

    if not bytes then
        self.fatal = true
    end

    self.closed = true

    return bytes, err
end
_M.send_close = send_close

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
        local bytes, err = send_close(self)
        if not bytes then
            return nil, "failed to send close frame: " .. err
        end
    end

    return sock.close()
end

return _M
