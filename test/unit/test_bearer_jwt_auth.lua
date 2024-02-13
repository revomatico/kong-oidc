local lu = require("luaunit")
TestHandler = require("test.unit.mockable_case"):extend()


function TestHandler:setUp()
  TestHandler.super:setUp()

  package.loaded["resty.openidc"] = nil
  self.module_resty = { openidc = {} }
  package.preload["resty.openidc"] = function()
    return self.module_resty.openidc
  end

  self.handler = require("kong.plugins.oidc.handler")
end

function TestHandler:tearDown()
  TestHandler.super:tearDown()
end

function TestHandler:test_bearer_jwt_auth_success()
  ngx.req.get_headers = function() return {Authorization = "Bearer xxx"} end
  ngx.encode_base64 = function(x) return "eyJzdWIiOiJzdWIifQ==" end

  self.module_resty.openidc.get_discovery_doc = function(opts)
    return { issuer = "https://oidc" }
  end

  self.module_resty.openidc.bearer_jwt_verify = function(opts)
    token = {
        iss = "https://oidc",
        sub = "sub111",
        aud = "aud222",
        groups = { "users" }
    }
    return token, nil, "xxx"
  end

  self.handler:access({
    bearer_jwt_auth_enable = "yes",
    client_id = "aud222",
    groups_claim = "groups",
    userinfo_header_name = "x-userinfo"
  })
  lu.assertEquals(ngx.ctx.authenticated_credential.id, "sub111")
  lu.assertEquals(kong.ctx.shared.authenticated_groups, { "users" })
end

function TestHandler:test_bearer_jwt_auth_fail()
  ngx.req.get_headers = function() return {Authorization = "Bearer xxx"} end
  local called_authenticate
  self.module_resty.openidc.get_discovery_doc = function(opts)
    return { issuer = "https://oidc" }
  end

  self.module_resty.openidc.bearer_jwt_verify = function(opts)
    return nil, "JWT expired"
  end

  self.module_resty.openidc.authenticate = function(opts)
    called_authenticate = true
    return nil, "error"
  end
  self.handler:access({bearer_jwt_auth_enable = "yes", client_id = "aud222"})
  lu.assertTrue(called_authenticate)
end

lu.run()
