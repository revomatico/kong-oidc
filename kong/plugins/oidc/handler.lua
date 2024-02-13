local OidcHandler = {
  VERSION = "1.3.0",
  PRIORITY = 1000,
}
local utils = require("kong.plugins.oidc.utils")
local filter = require("kong.plugins.oidc.filter")
local session = require("kong.plugins.oidc.session")
local consumers = require("kong.plugins.oidc.consumers")

function OidcHandler:init_worker()
  consumers.register_events()
end

function OidcHandler:access(config)
  local oidcConfig = utils.get_options(config, ngx)

  -- partial support for plugin chaining: allow skipping requests, where higher priority
  -- plugin has already set the credentials. The 'config.anomyous' approach to define
  -- "and/or" relationship between auth plugins is not utilized
  if oidcConfig.skip_already_auth_requests and kong.client.get_credential() then
    ngx.log(ngx.DEBUG, "OidcHandler ignoring already auth request: " .. ngx.var.request_uri)
    return
  end

  if filter.shouldProcessRequest(oidcConfig) then
    session.configure(config)
    handle(oidcConfig)
  else
    ngx.log(ngx.DEBUG, "OidcHandler ignoring request, path: " .. ngx.var.request_uri)
  end

  ngx.log(ngx.DEBUG, "OidcHandler done")
end

function handle(oidcConfig)
  local response

  --- bearer token first
  if oidcConfig.bearer_jwt_auth_enable then
    response = verify_bearer_jwt(oidcConfig)
    if response then
      ngx.log(ngx.DEBUG, "Verified bearer token: " .. utils.dump(response))
      utils.setCredentials(response)
      utils.injectGroups(response, oidcConfig.groups_claim)
      utils.injectHeaders(oidcConfig.header_names, oidcConfig.header_claims, { response })
      if not oidcConfig.disable_userinfo_header then
        utils.injectUser(response, oidcConfig.userinfo_header_name)
      end
    end
  end

  -- introspection second
  if response == nil and oidcConfig.introspection_endpoint then
    response = introspect(oidcConfig)
    if response then
      utils.setCredentials(response)
      utils.injectGroups(response, oidcConfig.groups_claim)
      utils.injectHeaders(oidcConfig.header_names, oidcConfig.header_claims, { response })
      if not oidcConfig.disable_userinfo_header then
        utils.injectUser(response, oidcConfig.userinfo_header_name)
      end
    end
  end

  -- finally authenticate if necessary and bearer_only is enabled
  -- if bearer mode only we don't need to authenticate.
  -- this also allows client_id and client_secret to be optional as
  -- these are not required for a bearer only flow with jwks
  if response == nil and not oidcConfig.bearer_only then
    response = make_oidc(oidcConfig)
    if response then
      if response.user or response.id_token then
        -- is there any scenario where lua-resty-openidc would not provide id_token?
        utils.setCredentials(response.user or response.id_token)
      end
      if response.user and response.user[oidcConfig.groups_claim] ~= nil then
        utils.injectGroups(response.user, oidcConfig.groups_claim)
      elseif response.id_token then
        utils.injectGroups(response.id_token, oidcConfig.groups_claim)
      end
      utils.injectHeaders(oidcConfig.header_names, oidcConfig.header_claims, { response.user, response.id_token })
      if (not oidcConfig.disable_userinfo_header
            and response.user) then
        utils.injectUser(response.user, oidcConfig.userinfo_header_name)
      end
      if (not oidcConfig.disable_access_token_header
            and response.access_token) then
        utils.injectAccessToken(response.access_token, oidcConfig.access_token_header_name,
          oidcConfig.access_token_as_bearer)
      end
      if (not oidcConfig.disable_id_token_header
            and response.id_token) then
        utils.injectIDToken(response.id_token, oidcConfig.id_token_header_name)
      end
    end
  end

  if not response then
    return kong.response.error(ngx.HTTP_UNAUTHORIZED)
  end

  -- authorize scopes(add other validation if needed)
  -- if response comes from authenticate, we need to decode the access token to verify the scopes for authorization
  if oidcConfig.authorization_scopes_required then
    if (response.access_token) then
      local res, err = require("resty.openidc").bearer_jwt_verify(oidcConfig)
      -- something went very wrong with the token
      if err then
        return kong.response.error(ngx.HTTP_UNAUTHORIZED)
      end
      response = res
    end
    if not authorize_scopes(oidcConfig, response) then
      return kong.response.error(ngx.HTTP_FORBIDDEN)
    end
  end

  -- set credentials and consumer if consumer_claim is set
  if oidcConfig.consumer_claim then
    local consumer = get_consumer(oidcConfig, response)
    if not consumer and not oidcConfig.consumer_optional then
      kong.log.err("Consumer not found and consumer_optional is false, returning 403 forbidden")
      return kong.response.error(ngx.HTTP_FORBIDDEN)
    end
    utils.set_consumer(consumer)
  end
end

function make_oidc(oidcConfig)
  ngx.log(ngx.DEBUG, "OidcHandler calling authenticate, requested path: " .. ngx.var.request_uri)
  local unauth_action = oidcConfig.unauth_action
  if unauth_action ~= "auth" then
    -- constant for resty.oidc library
    unauth_action = "deny"
  end
  local res, err = require("resty.openidc").authenticate(oidcConfig, ngx.var.request_uri, unauth_action)

  if err then
    if err == 'unauthorized request' then
      return kong.response.error(ngx.HTTP_UNAUTHORIZED)
    else
      if oidcConfig.recovery_page_path then
        ngx.log(ngx.DEBUG, "Redirecting to recovery page: " .. oidcConfig.recovery_page_path)
        ngx.redirect(oidcConfig.recovery_page_path)
      end
      return kong.response.error(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
  end
  return res
end

function introspect(oidcConfig)
  if utils.has_bearer_access_token() or oidcConfig.bearer_only then
    local res, err
    if oidcConfig.use_jwks == "yes" then
      res, err = require("resty.openidc").bearer_jwt_verify(oidcConfig)
    else
      res, err = require("resty.openidc").introspect(oidcConfig)
    end
    if err then
      if oidcConfig.bearer_only then
        ngx.header["WWW-Authenticate"] = 'Bearer realm="' .. oidcConfig.realm .. '",error="' .. err .. '"'
        return kong.response.error(ngx.HTTP_UNAUTHORIZED)
      end
      return nil
    end
    if oidcConfig.validate_scope == "yes" then
      local validScope = false
      if res.scope then
        for scope in res.scope:gmatch("([^ ]+)") do
          if scope == oidcConfig.scope then
            validScope = true
            break
          end
        end
      end
      if not validScope then
        kong.log.err("Scope validation failed")
        return kong.response.error(ngx.HTTP_FORBIDDEN)
      end
    end
    ngx.log(ngx.DEBUG, "OidcHandler introspect succeeded, requested path: " .. ngx.var.request_uri)
    return res
  end
  return nil
end

function verify_bearer_jwt(oidcConfig)
  if not utils.has_bearer_access_token() then
    return nil
  end
  -- setup controlled configuration for bearer_jwt_verify
  local opts = {
    accept_none_alg = false,
    accept_unsupported_alg = false,
    token_signing_alg_values_expected = oidcConfig.bearer_jwt_auth_signing_algs,
    discovery = oidcConfig.discovery,
    timeout = oidcConfig.timeout,
    ssl_verify = oidcConfig.ssl_verify
  }

  local discovery_doc, err = require("resty.openidc").get_discovery_doc(opts)
  if err then
    kong.log.err('Discovery document retrieval for Bearer JWT verify failed')
    return nil
  end

  local allowed_auds = oidcConfig.bearer_jwt_auth_allowed_auds or oidcConfig.client_id

  local jwt_validators = require "resty.jwt-validators"
  jwt_validators.set_system_leeway(120)
  local claim_spec = {
    -- mandatory for id token: iss, sub, aud, exp, iat
    iss = jwt_validators.equals(discovery_doc.issuer),
    sub = jwt_validators.required(),
    aud = function(val) return utils.has_common_item(val, allowed_auds) end,
    exp = jwt_validators.is_not_expired(),
    iat = jwt_validators.required(),
    -- optional validations
    nbf = jwt_validators.opt_is_not_before(),
  }

  local json, err, token = require("resty.openidc").bearer_jwt_verify(opts, claim_spec)
  if err then
    kong.log.err('Bearer JWT verify failed: ' .. err)
    return nil
  end
  return json
end

function authorize_scopes(oidcConfig, res)
  if not oidcConfig.authorization_scopes_required then
    return true
  end
  local validScope = false
  local scopes_required = oidcConfig.authorization_scopes_required
  ngx.log(ngx.DEBUG, "Validating scopes: [" .. table.concat(scopes_required, " ") .. "] against [" .. res.scope .. "]")
  if res.scope then
    local res_scope = {}
    for scope in res.scope:gmatch("([^ ]+)") do table.insert(res_scope, scope) end
    validScope = utils.containsAll(res_scope, scopes_required)
  end
  if not validScope then
    kong.log.err("Scope validation failed, missing required scopes: " .. table.concat(scopes_required, " "))
  end
  return validScope
end

function get_consumer(oidcConfig, res)
  ngx.log(ngx.DEBUG, "Looking up consumer by claim: " .. oidcConfig.consumer_claim)
  local claim = res[oidcConfig.consumer_claim]
  if not claim then
    return nil
  end
  return consumers.get_consumer_by(claim, oidcConfig.consumer_by)
end

return OidcHandler
