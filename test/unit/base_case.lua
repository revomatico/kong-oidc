package.path = package.path .. ";test/lib/?.lua;;" -- kong & co

local Object = require "test.unit.classic"
local BaseCase = Object:extend()


function BaseCase:setUp()
end

function BaseCase:tearDown()
end


return BaseCase
