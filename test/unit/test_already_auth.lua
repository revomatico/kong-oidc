local lu = require("luaunit")
TestHandler = require("test.unit.mockable_case"):extend()


function TestHandler:setUp()
  TestHandler.super:setUp()

  package.loaded["resty.openidc"] = nil
  self.module_resty = { openidc = {} }
  package.preload["resty.openidc"] = function()
    return self.module_resty.openidc
  end

  self.handler = require("kong.plugins.oidc.handler")()
end

function TestHandler:tearDown()
  TestHandler.super:tearDown()
end

function TestHandler:test_skip_already_auth_has_cred()
  kong.client.get_credential = function() return { consumer_id = "user" } end
  local called_authenticate
  self.module_resty.openidc.authenticate = function(opts)
    called_authenticate = true
    return nil, "error"
  end
  self.handler:access({ skip_already_auth_requests = "yes" })
  lu.assertNil(called_authenticate)
end

function TestHandler:test_skip_already_auth_has_no_cred()
  kong.client.get_credential = function() return nil end
  local called_authenticate
  self.module_resty.openidc.authenticate = function(opts)
    called_authenticate = true
    return nil, "error"
  end
  self.handler:access({ skip_already_auth_requests = "yes" })
  lu.assertTrue(called_authenticate)
end


lu.run()
