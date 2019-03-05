local skynet = require "skynet"
local socket = require "http.sockethelper"
local url = require "http.url"
local internal = require "http.internal"
local dns = require "skynet.dns"
local string = string
local table = table
local ssl = require "ssl"

local ssl_ctx

local https = {}

local function request(fd, method, host, url, recvheader, header, content)
	local read = socket.readfunc(fd)
	local write = socket.writefunc(fd)

	ssl_ctx = ssl_ctx or ssl.newctx("./test/client-cert.pem", "./test/client-key.pem", false)
	local s = ssl.new(ssl_ctx, false, read, write)

	read = function ()
		return s:read()
	end

	write = function (data)
		return s:write(data)
	end


	local header_content = ""
	if header then
		if not header.host then
			header.host = host
		end
		for k,v in pairs(header) do
			header_content = string.format("%s%s:%s\r\n", header_content, k, v)
		end
	else
		header_content = string.format("host:%s\r\n",host)
	end

	if content then
		local data = string.format("%s %s HTTP/1.1\r\n%scontent-length:%d\r\n\r\n", method, url, header_content, #content)
		write(data)
		write(content)
	else
		url = "https://www.baidu.com/"
		local request_header = string.format("%s %s HTTP/1.1\r\n%scontent-length:0\r\n\r\n", method, url, header_content)
		print(request_header)
		write(request_header)
	end

	local tmpline = {}
	local body = internal.recvheader(read, tmpline, "")
	if not body then
		error(socket.socket_error)
	end

	local statusline = tmpline[1]
	local code, info = statusline:match "HTTP/[%d%.]+%s+([%d]+)%s+(.*)$"
	code = assert(tonumber(code))

	local header = internal.parseheader(tmpline,2,recvheader or {})
	if not header then
		error("Invalid HTTP response header")
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
			body = body .. socket.readall(fd)
		end
	end

	return code, body
end

local async_dns

function https.dns(server,port)
	async_dns = true
	dns.server(server,port)
end

function https.request(method, host, url, recvheader, header, content)
	local timeout = https.timeout	-- get https.timeout before any blocked api
	local hostname, port = host:match"([^:]+):?(%d*)$"
	if port == "" then
		port = 443 
	else
		port = tonumber(port)
	end
	if async_dns and not hostname:match(".*%d+$") then
		hostname = dns.resolve(hostname)
	end

	local fd = socket.connect(hostname, port, timeout)
	if not fd then
		error(string.format("http connect error host:%s, port:%s, timeout:%s", hostname, port, timeout))
		return
	end

	local finish
	if timeout then
		skynet.timeout(timeout, function()
			if not finish then
				socket.shutdown(fd)	-- shutdown the socket fd, need close later.
			end
		end)
	end
	local ok , statuscode, body = pcall(request, fd,method, host, url, recvheader, header, content)
	finish = true
	socket.close(fd)
	if ok then
		return statuscode, body
	else
		error(statuscode)
	end
end

function https.get(...)
	return https.request("GET", ...)
end

local function escape(s)
	return (string.gsub(s, "([^A-Za-z0-9_])", function(c)
		return string.format("%%%02X", string.byte(c))
	end))
end

function https.post(host, url, form, recvheader)
	local header = {
		["content-type"] = "application/x-www-form-urlencoded"
	}
	local body = {}
	for k,v in pairs(form) do
		table.insert(body, string.format("%s=%s",escape(k),escape(v)))
	end

	return https.request("POST", host, url, recvheader, header, table.concat(body , "&"))
end

return https
