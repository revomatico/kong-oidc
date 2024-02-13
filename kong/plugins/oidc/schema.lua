local typedefs = require "kong.db.schema.typedefs"

return {
  name = "kong-oidc",
  fields = {
    {
      -- this plugin will only be applied to Services or Routes
      consumer = typedefs.no_consumer
    },
    {
      -- this plugin will only run within Nginx HTTP module
      protocols = typedefs.protocols_http
    },
    {
      config = {
        type = "record",
        fields = {
          {
            client_id = {
              type = "string",
              required = false
            }
          },
          {
            client_secret = {
              type = "string",
              required = false
            }
          },
          {
            discovery = {
              type = "string",
              required = true,
              default = "https://.well-known/openid-configuration"
            }
          },
          {
            introspection_endpoint = {
              type = "string",
              required = false
            }
          },
          {
            introspection_endpoint_auth_method = {
              type = "string",
              required = false
            }
          },
          {
            introspection_cache_ignore = {
              type = "string",
              required = true,
              default = "no"
            }
          },
          {
            timeout = {
              type = "number",
              required = false
            }
          },
          {
            bearer_only = {
              type = "string",
              required = true,
              default = "no"
            }
          },
          {
            realm = {
              type = "string",
              required = true,
              default = "kong"
            }
          },
          {
            redirect_uri = {
              type = "string"
            }
          },
          {
            scope = {
              type = "string",
              required = true,
              default = "openid"
            }
          },
          {
            validate_scope = {
              type = "string",
              required = true,
              default = "no"
            }
          },
          {
            response_type = {
              type = "string",
              required = true,
              default = "code"
            }
          },
          {
            ssl_verify = {
              type = "string",
              required = true,
              default = "no"
            }
          },
          {
            use_jwks = {
              type = "string",
              required = true,
              default = "no"
            }
          },
          {
            token_endpoint_auth_method = {
              type = "string",
              required = true,
              default = "client_secret_post"
            }
          },
          {
            session_secret = {
              type = "string",
              required = false
            }
          },
          {
            recovery_page_path = {
              type = "string"
            }
          },
          {
            logout_path = {
              type = "string",
              required = false,
              default = "/logout"
            }
          },
          {
            redirect_after_logout_uri = {
              type = "string",
              required = false,
              default = "/"
            }
          },
          {
            redirect_after_logout_with_id_token_hint = {
              type = "string",
              required = false,
              default = "no"
            }
          },
          {
            post_logout_redirect_uri = {
              type = "string",
              required = false
            }
          },
          {
            unauth_action = {
              type = "string",
              required = false,
              default = "auth"
            }
          },
          {
            filters = {
              type = "string"
            }
          },
          {
            ignore_auth_filters = {
              type = "string",
              required = false
            }
          },
          {
            userinfo_header_name = {
              type = "string",
              required = false,
              default = "X-USERINFO"
            }
          },
          {
            id_token_header_name = {
              type = "string",
              required = false,
              default = "X-ID-Token"
            }
          },
          {
            access_token_header_name = {
              type = "string",
              required = false,
              default = "X-Access-Token"
            }
          },
          {
            access_token_as_bearer = {
              type = "string",
              required = false,
              default = "no"
            }
          },
          {
            disable_userinfo_header = {
              type = "string",
              required = false,
              default = "no"
            }
          },
          {
            disable_id_token_header = {
              type = "string",
              required = false,
              default = "no"
            }
          },
          {
            disable_access_token_header = {
              type = "string",
              required = false,
              default = "no"
            }
          },
          {
            revoke_tokens_on_logout = {
              type = "string",
              required = false,
              default = "no"
            }
          },
          {
            groups_claim = {
              type = "string",
              required = false,
              default = "groups"
            }
          },
          {
            skip_already_auth_requests = {
              type = "string",
              required = false,
              default = "no"
            }
          },
          {
            bearer_jwt_auth_enable = {
              type = "string",
              required = false,
              default = "no"
            }
          },
          {
            bearer_jwt_auth_allowed_auds = {
              type = "array",
              required = false,
              elements = {
                type = "string"
              },
            }
          },
          {
            bearer_jwt_auth_signing_algs = {
              type = "array",
              required = true,
              elements = {
                type = "string"
              },
              default = {
                "RS256"
              }
            }
          },
          {
            header_names = {
              type = "array",
              required = true,
              elements = {
                type = "string"
              },
              default = {}
            }
          },
          {
            header_claims = {
              type = "array",
              required = true,
              elements = {
                type = "string"
              },
              default = {}
            }
          },
          {
            http_proxy = {
              type = "string",
              required = false
            }
          },
          {
            https_proxy = {
              type = "string",
              required = false
            }
          },
          {
            authorization_scopes_required = {
              required = false,
              type = "array",
              elements = {
                type = "string"
              }
            }
          },
          {
            consumer_claim = {
              required = false,
              type = "string"
            }
          },
          {
            consumer_by = {
              required = false,
              type = "string",
              default = "id_or_username",
              one_of = {
                "id_or_username",
                "custom_id"
              }
            }
          },
          {
            consumer_optional = {
              required = false,
              type = "boolean",
              default = false
            }
          }
        }
      }
    }
  }
}
