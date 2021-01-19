local BaseCase = require("test.unit.base_case")
local MockableCase = BaseCase:extend()


function MockableCase:setUp()
  MockableCase.super:setUp()
  self.logs = {}
  self.mocked_ngx = {
    DEBUG = "debug",
    ERR = "error",
    HTTP_UNAUTHORIZED = 401,
    ctx = {},
    header = {},
    var = {request_uri = "/"},
    req = {
      get_uri_args = function(...) end,
      set_header = function(...) end,
      get_headers = function(...) end
    },
    log = function(...)
      self.logs[#self.logs+1] = table.concat({...}, " ")
      print("ngx.log: ", self.logs[#self.logs])
    end,
    say = function(...) end,
    exit = function(...) end,
    redirect = function(...) end,
    config = {
      subsystem = "http"
    }
  }
  self.ngx = _G.ngx
  _G.ngx = self.mocked_ngx

  self.mocked_kong = {
    client = {
      authenticate = function(consumer, credential)
        ngx.ctx.authenticated_consumer = consumer
        ngx.ctx.authenticated_credential = credential
      end
    },
    service = {
      request = {
        clear_header = function(...) end,
        set_header = function(...) end
      }
    },
    log = {
      err = function(...) end
    },
    ctx = {
      shared = {}
    }
  }
  self.kong = _G.kong
  _G.kong = self.mocked_kong

  self.resty = package.loaded.resty
  package.loaded["resty.http"] = nil
  package.preload["resty.http"] = function()
    return {encode = function(...) return "encoded" end}
  end

  self.cjson = package.loaded.cjson
  package.loaded.cjson = nil
  package.preload["cjson"] = function()
    return {
      encode = function(...) return "encoded" end,
      decode = function(...) return {sub = "sub"} end
    }
  end
end

function MockableCase:tearDown()
  MockableCase.super:tearDown()
  _G.ngx = self.ngx
  _G.kong = self.kong
  package.loaded.resty = self.resty
  package.loaded.cjson = self.cjson
end

function MockableCase:log_contains(str)
  return table.concat(self.logs, "//"):find(str) and true or false
end

function MockableCase:__tostring()
  return "MockableCase"
end


return MockableCase
