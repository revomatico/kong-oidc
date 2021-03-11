local cjson = require("cjson")
local constants = require "kong.constants"

local M = {}

local function parseFilters(csvFilters)
  local filters = {}
  if (not (csvFilters == nil)) and (not (csvFilters == ",")) then
    for pattern in string.gmatch(csvFilters, "[^,]+") do
      table.insert(filters, pattern)
    end
  end
  return filters
end

local function formatAsBearerToken(token)
  return "Bearer " .. token
end

function M.get_redirect_uri(ngx)
  local function drop_query()
    local uri = ngx.var.request_uri
    ngx.log(ngx.DEBUG, "drop_query uri=" .. uri)
    local x = uri:find("?")
    if x then
      return uri:sub(1, x - 1)
    else
      return uri
    end
  end

  local function tackle_slash(path)
    ngx.log(ngx.DEBUG, "tackle_slash path=" .. path)
    local args = ngx.req.get_uri_args()
    if args and args.code then
      ngx.log(ngx.DEBUG, "tackle_slash args.code=" .. args.code)
      return path
    else
      return "/cb"
    end
  end

  return tackle_slash(drop_query())
end

function M.get_options(config, ngx)
  return {
    client_id = config.client_id,
    client_secret = config.client_secret,
    discovery = config.discovery,
    introspection_endpoint = config.introspection_endpoint,
    timeout = config.timeout,
    introspection_endpoint_auth_method = config.introspection_endpoint_auth_method,
    bearer_only = config.bearer_only,
    realm = config.realm,
    redirect_uri = config.redirect_uri or M.get_redirect_uri(ngx),
    scope = config.scope,
    response_type = config.response_type,
    ssl_verify = config.ssl_verify,
    use_jwks = config.use_jwks,
    token_endpoint_auth_method = config.token_endpoint_auth_method,
    recovery_page_path = config.recovery_page_path,
    filters = parseFilters((config.filters or "") .. "," .. (config.ignore_auth_filters or "")),
    logout_path = config.logout_path,
    redirect_after_logout_uri = config.redirect_after_logout_uri,
    unauth_action = config.unauth_action,
    userinfo_header_name = config.userinfo_header_name,
    id_token_header_name = config.id_token_header_name,
    access_token_header_name = config.access_token_header_name,
    access_token_as_bearer = config.access_token_as_bearer == "yes",
    disable_userinfo_header = config.disable_userinfo_header == "yes",
    disable_id_token_header = config.disable_id_token_header == "yes",
    disable_access_token_header = config.disable_access_token_header == "yes",
    groups_claim = config.groups_claim,
    skip_already_auth_requests = config.skip_already_auth_requests == "yes",
    bearer_jwt_auth_enable = config.bearer_jwt_auth_enable == "yes",
    bearer_jwt_auth_allowed_auds = config.bearer_jwt_auth_allowed_auds,
    bearer_jwt_auth_signing_algs = config.bearer_jwt_auth_signing_algs,
    header_names = config.header_names or {},
    header_claims = config.header_claims or {}
  }
end

function M.exit(httpStatusCode, message, ngxCode)
  ngx.status = httpStatusCode
  ngx.say(message)
  ngx.exit(ngxCode)
end


-- Function set_consumer is derived from the following kong auth plugins:
-- https://github.com/Kong/kong/blob/2.2.0/kong/plugins/ldap-auth/access.lua
-- https://github.com/Kong/kong/blob/2.2.0/kong/plugins/oauth2/access.lua
-- Copyright 2016-2020 Kong Inc. Licensed under the Apache License, Version 2.0
-- https://github.com/Kong/kong/blob/2.2.0/LICENSE
local function set_consumer(consumer, credential)
  kong.client.authenticate(consumer, credential)

  local set_header = kong.service.request.set_header
  local clear_header = kong.service.request.clear_header

  if consumer and consumer.id then
    set_header(constants.HEADERS.CONSUMER_ID, consumer.id)
  else
    clear_header(constants.HEADERS.CONSUMER_ID)
  end

  if consumer and consumer.custom_id then
    set_header(constants.HEADERS.CONSUMER_CUSTOM_ID, consumer.custom_id)
  else
    clear_header(constants.HEADERS.CONSUMER_CUSTOM_ID)
  end

  if consumer and consumer.username then
    set_header(constants.HEADERS.CONSUMER_USERNAME, consumer.username)
  else
    clear_header(constants.HEADERS.CONSUMER_USERNAME)
  end

  if credential and credential.sub then
    set_header(constants.HEADERS.CREDENTIAL_IDENTIFIER, credential.sub)
  else
    clear_header(constants.HEADERS.CREDENTIAL_IDENTIFIER)
  end

  clear_header(constants.HEADERS.CREDENTIAL_USERNAME)

  if credential then
    clear_header(constants.HEADERS.ANONYMOUS)
  else
    set_header(constants.HEADERS.ANONYMOUS, true)
  end
end

function M.injectAccessToken(accessToken, headerName, bearerToken)
  ngx.log(ngx.DEBUG, "Injecting " .. headerName)
  local token = accessToken
  if (bearerToken) then
    token = formatAsBearerToken(token)
  end
  ngx.req.set_header(headerName, token)
end

function M.injectIDToken(idToken, headerName)
  ngx.log(ngx.DEBUG, "Injecting " .. headerName)
  local tokenStr = cjson.encode(idToken)
  ngx.req.set_header(headerName, ngx.encode_base64(tokenStr))
end

function M.setCredentials(user)
  local tmp_user = user
  tmp_user.id = user.sub
  tmp_user.username = user.preferred_username
  set_consumer(nil, tmp_user)
end

function M.injectUser(user, headerName)
  ngx.log(ngx.DEBUG, "Injecting " .. headerName)
  local userinfo = cjson.encode(user)
  ngx.req.set_header(headerName, ngx.encode_base64(userinfo))
end

function M.injectGroups(user, claim)
  if user[claim] ~= nil then
    kong.ctx.shared.authenticated_groups = user[claim]
  end
end

function M.injectHeaders(header_names, header_claims, sources)
  if #header_names ~= #header_claims then
    kong.log.err('Different number of elements provided in header_names and header_claims. Headers will not be added.')
    return
  end
  for i = 1, #header_names do
    local header, claim
    header = header_names[i]
    claim = header_claims[i]
    kong.service.request.clear_header(header)
    for j = 1, #sources do
      local source
      source = sources[j]
      if (source and source[claim]) then
        kong.service.request.set_header(header, source[claim])
        break
      end
    end
  end
end

function M.has_bearer_access_token()
  local header = ngx.req.get_headers()['Authorization']
  if header and header:find(" ") then
    local divider = header:find(' ')
    if string.lower(header:sub(0, divider-1)) == string.lower("Bearer") then
      return true
    end
  end
  return false
end

-- verify if tables t1 and t2 have at least one common string item
-- instead of table, also string can be provided as t1 or t2
function M.has_common_item(t1, t2)
  if t1 == nil or t2 == nil then
    return false
  end
  if type(t1) == "string" then
    t1 = { t1 }
  end
  if type(t2) == "string" then
    t2 = { t2 }
  end
  local i1, i2
  for _, i1 in pairs(t1) do
    for _, i2 in pairs(t2) do
      if type(i1) == "string" and type(i2) == "string" and i1 == i2 then
        return true
      end
    end
  end
  return false
end

return M
