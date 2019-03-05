local core = require "ssl.core"

local ssl = {}

local meta = {}

function meta:read(sz)
    while true do
        local len, data = core.ssl_read(self.ud, sz)
        if len > 0 then
            return data
        else
            local data = self.input()
            if data then
                core.bio_write(self.ud, data)
            else
                return false
            end
        end
    end
end

function meta:write(data)
    local ret = core.ssl_write(self.ud, data)
    if ret > 0 then
        local sz, data = core.bio_read(self.ud)
        if sz > 0 then
            self.output(data)
        end
    end
end

local function do_handshake(obj)
    local indata
    if obj.isserver then
        indata = obj.input()
        if not indata then
            error("handshake failed!")
        end
    end
    repeat
        if indata then
            core.bio_write(obj.ud, indata)
            indata = nil
        end
        local ret = core.ssl_do_handshake(obj.ud)
        local sz, outdata = core.bio_read(obj.ud)
        if sz > 0 then
            obj.output(outdata)
        else
            if ret == 1 then
                break
            else
                indata = obj.input()
                if not indata then
                    error("handshake failed!")
                end
            end
        end
    until core.ssl_is_init_finished(obj.ud)
end

function ssl.newctx(certfile, keyfile, isserver)
    return core.ssl_ctx_new(certfile, keyfile, isserver)
end

function ssl.new(ctx, isserver, input, output)
    local ud = core.ssl_new(ctx, isserver)
    local obj = {ud=ud, input=input, output=output, isserver=isserver}
    do_handshake(obj)
    return setmetatable(obj, {__index=meta})
end

return ssl
