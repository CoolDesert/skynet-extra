local skynet = require "skynet"

skynet.start(function()
	skynet.error("Server start")

	if not skynet.getenv "daemon" then
		skynet.newservice("console")
	end

	skynet.exit()
end)
