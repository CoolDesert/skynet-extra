-- Copyright (C) Yichun Zhang (agentzh)
-- This file is modified version from https://github.com/openresty/lua-resty-websocket
-- The license is under the BSD license.
-- Modified by CoolDesert

local byte = string.byte
local char = string.char
local sub = string.sub
local tostring = tostring
local concat = table.concat
local str_char = string.char
local rand = math.random
local type = type

local types = {
    [0x0] = "continuation",
    [0x1] = "text",
    [0x2] = "binary",
    [0x8] = "close",
    [0x9] = "ping",
    [0xa] = "pong",
}

local _M = {}

function _M.recv_frame(sock, max_payload_len, force_masking)
    local data, err = sock.receive(2)
    if not data then
        return nil, nil, "failed to receive the first 2 bytes: " .. err
    end

    local fst, snd = byte(data, 1, 2)

    local fin = (fst & 0x80) ~= 0
    -- print("fin: ", fin)

    if (fst & 0x70) ~= 0 then
        return nil, nil, "bad RSV1, RSV2, or RSV3 bits"
    end

    local opcode = (fst & 0x0f)
    -- print("opcode: ", tohex(opcode))

    if opcode >= 0x3 and opcode <= 0x7 then
        return nil, nil, "reserved non-control frames"
    end

    if opcode >= 0xb and opcode <= 0xf then
        return nil, nil, "reserved control frames"
    end

    local mask = (snd & 0x80) ~= 0

    -- print("recv_frame: mask bit: ", mask and 1 or 0)

    if force_masking and not mask then
        return nil, nil, "frame unmasked"
    end

    local payload_len = (snd & 0x7f)
    -- print("payload len: ", payload_len)

    if payload_len == 126 then
        local data, err = sock.receive(2)
        if not data then
            return nil, nil, "failed to receive the 2 byte payload length: "
                             .. (err or "unknown")
        end

        payload_len = ((byte(data, 1) << 8) | byte(data, 2))

    elseif payload_len == 127 then
        local data, err = sock.receive(8)
        if not data then
            return nil, nil, "failed to receive the 8 byte payload length: "
                             .. (err or "unknown")
        end

        if byte(data, 1) ~= 0
           or byte(data, 2) ~= 0
           or byte(data, 3) ~= 0
           or byte(data, 4) ~= 0
        then
            return nil, nil, "payload len too large"
        end

        local fifth = byte(data, 5)
        if (fifth & 0x80) ~= 0 then
            return nil, nil, "payload len too large"
        end

        payload_len = fifth << 24 | byte(data, 6) << 16 | byte(data, 7) << 8 | byte(data, 8)
    end

    if (opcode & 0x8) ~= 0 then
        -- being a control frame
        if payload_len > 125 then
            return nil, nil, "too long payload for control frame"
        end

        if not fin then
            return nil, nil, "fragmented control frame"
        end
    end

    -- print("payload len: ", payload_len, ", max payload len: ",
          -- max_payload_len)

    if payload_len > max_payload_len then
        return nil, nil, "exceeding max payload len"
    end

    local rest
    if mask then
        rest = payload_len + 4

    else
        rest = payload_len
    end
    -- print("rest: ", rest)

    local data
    if rest > 0 then
        data, err = sock.receive(rest)
        if not data then
            return nil, nil, "failed to read masking-len and payload: "
                             .. (err or "unknown")
        end
    else
        data = ""
    end

    -- print("received rest")

    if opcode == 0x8 then
        -- being a close frame
        if payload_len > 0 then
            if payload_len < 2 then
                return nil, nil, "close frame with a body must carry a 2-byte"
                                 .. " status code"
            end

            local msg, code
            if mask then
                local fst = (byte(data, 4 + 1) ~ byte(data, 1))
                local snd = (byte(data, 4 + 2) ~ byte(data, 2))
                code = ((fst << 8) | snd)

                if payload_len > 2 then
                    -- TODO string.buffer optimizations
                    local bytes = {}
                    for i = 3, payload_len do
                        bytes[i - 2] = str_char((byte(data, 4 + i) ~ byte(data, (i - 1) % 4 + 1)))
                    end
                    msg = concat(bytes)
                else
                    msg = ""
                end

            else
                local fst = byte(data, 1)
                local snd = byte(data, 2)
                code = ((fst << 8) | snd)

                -- print("parsing unmasked close frame payload: ", payload_len)

                if payload_len > 2 then
                    msg = sub(data, 3)

                else
                    msg = ""
                end
            end

            return msg, "close", code
        end

        return "", "close", nil
    end

    local msg
    if mask then
        -- TODO string.buffer optimizations
        local bytes = {}
        for i = 1, payload_len do
            bytes[i] = str_char((byte(data, 4 + i) ~ byte(data, (i - 1) % 4 + 1)))
        end
        msg = concat(bytes)
    else
        msg = data
    end

    return msg, types[opcode], not fin and "again" or nil
end


local function build_frame(fin, opcode, payload_len, payload, masking)
    -- XXX optimize this when we have string.buffer in LuaJIT 2.1
    local fst
    if fin then
        fst = 0x80 | opcode
    else
        fst = opcode
    end

    local snd, extra_len_bytes
    if payload_len <= 125 then
        snd = payload_len
        extra_len_bytes = ""

    elseif payload_len <= 65535 then
        snd = 126
        extra_len_bytes = char(((payload_len >> 8) & 0xff), (payload_len & 0xff))

    else
        if band(payload_len, 0x7fffffff) < payload_len then
            return nil, "payload too big"
        end

        snd = 127
        -- XXX we only support 31-bit length here
        extra_len_bytes = char(0, 0, 0, 0, ((payload_len >> 24) & 0xff),
                               ((payload_len >> 16) & 0xff),
                               ((payload_len >> 8) & 0xff),
                               (payload_len& 0xff))
    end

    local masking_key
    if masking then
        -- set the mask bit
        snd = snd | 0x80
        local key = rand(0xffffffff)
        masking_key = char(((key >> 24) & 0xff),
                           ((key >> 16) & 0xff),
                           ((key >> 8) & 0xff),
                           (key & 0xff))

        -- TODO string.buffer optimizations
        local bytes = {}
        for i = 1, payload_len do
            bytes[i] = str_char((byte(payload, i) ~ byte(masking_key, (i - 1) % 4 + 1)))
        end
        payload = concat(bytes)

    else
        masking_key = ""
    end

    return char(fst, snd) .. extra_len_bytes .. masking_key .. payload
end
_M.build_frame = build_frame


function _M.send_frame(sock, fin, opcode, payload, max_payload_len, masking)

    if not payload then
        payload = ""

    elseif type(payload) ~= "string" then
        payload = tostring(payload)
    end

    local payload_len = #payload

    if payload_len > max_payload_len then
        return nil, "payload too big"
    end

    if (opcode & 0x8) ~= 0 then
        -- being a control frame
        if payload_len > 125 then
            return nil, "too much payload for control frame"
        end
        if not fin then
            return nil, "fragmented control frame"
        end
    end

    local frame, err = build_frame(fin, opcode, payload_len, payload,
                                   masking)
    if not frame then
        return nil, "failed to build frame: " .. err
    end

    sock.send(frame)

    return true 
end


return _M
